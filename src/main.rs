use grammers_client::types::{Chat, Media, Message};
use grammers_client::{Client, Config, InitParams, InputMessage, SignInError, Update};
use grammers_session::Session;
use grammers_tl_types::enums::MessageEntity;
use grammers_tl_types::types::MessageEntityTextUrl;
use snafu::{whatever, ResultExt, Whatever};
use std::path::Path;
use tracing::{debug, error, info, instrument, warn};

mod config;
mod init_tracing;

async fn connect_and_login(config: &config::Telegram) -> Result<Client, Whatever> {
    let mut catch_up = false;

    let session = match &config.session_storage {
        Some(session_storage) => {
            let session_storage = Path::new(session_storage);
            if session_storage.exists() {
                info!("Loading saved session from {}", session_storage.display());
                // only request catch up when loading our own session, not a prepared or a new one
                catch_up = true;
                Some(Session::load_file(session_storage).whatever_context("Loading session")?)
            } else {
                info!("No session file found, creating a new session");
                None
            }
        }
        None => {
            warn!("No session storage configured, creating a new session. This will create dangling sessions on restarts!");
            None
        }
    };

    let session = match session {
        Some(session) => session,
        None => match &config.account {
            config::TelegramAccount::PreparedSession { session } => {
                info!("Loading session from config");
                Session::load(session).whatever_context("Loading session")?
            }
            _ => Session::new(),
        },
    };

    let client = Client::connect(Config {
        session,
        api_id: config.api_id,
        api_hash: config.api_hash.clone(),
        params: InitParams {
            catch_up,
            ..Default::default()
        },
    })
    .await
    .whatever_context("Connecting to telegram")?;

    if !client
        .is_authorized()
        .await
        .whatever_context("failed to check whether we are signed in")?
    {
        info!("Not signed in, signing in...");

        match &config.account {
            config::TelegramAccount::PreparedSession { .. } => {
                whatever!("Prepared session is not signed in, please sign in manually and provide the session file")
            }
            config::TelegramAccount::Bot { token } => {
                info!("Signing in as bot");
                client
                    .bot_sign_in(token)
                    .await
                    .whatever_context("Signing in as bot")?;
            }
            config::TelegramAccount::User { phone } => {
                info!("Signing in as user");
                let login_token = client
                    .request_login_code(phone)
                    .await
                    .whatever_context("Requesting login code")?;

                info!("Asked telegram for login code, waiting for it to be entered");

                let mut logic_code = String::new();
                std::io::stdin()
                    .read_line(&mut logic_code)
                    .whatever_context("Reading login code")?;
                let logic_code = logic_code.strip_suffix('\n').unwrap();

                match client.sign_in(&login_token, &logic_code).await {
                    Ok(_) => {}
                    Err(SignInError::PasswordRequired(password_token)) => {
                        info!(
                            "2FA Password required, asking for it. Password hint: {}",
                            password_token.hint().unwrap()
                        );
                        let mut password = String::new();
                        std::io::stdin()
                            .read_line(&mut password)
                            .whatever_context("Reading password")?;
                        let password = password.strip_suffix('\n').unwrap();

                        client
                            .check_password(password_token, password)
                            .await
                            .whatever_context("Checking password")?;
                    }
                    Err(e) => {
                        return Err(e).whatever_context("Signing in as user");
                    }
                }
            }
        }

        if config.session_storage.is_some() {
            info!("Signed in, saving session");
            save_session(&client, config)?;
        } else {
            warn!("Signed in, but no session storage configured. This will leave dangling sessions on restarts!");
        }
    }

    Ok(client)
}

// TODO: make an update summary for the instrument macro

#[instrument]
fn check_link(link: &str) -> Option<String> {
    // 1. check if it's a youtube link
    // 2. check if it has the `si` parameter
    // 3. remove the `si` parameter

    let Ok(mut parse) = url::Url::parse(link) else {
        warn!("Failed to parse url: {}", link);
        return None;
    };

    let Some("youtube.com" | "www.youtube.com" | "youtu.be") = parse.host_str() else {
        info!("Likely not a youtube link: {}", link);
        return None;
    };

    let params = parse
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>();

    let mut needs_patch = false;
    {
        let mut params_serializer = parse.query_pairs_mut();
        params_serializer.clear();
        for (key, value) in params {
            if key == "si" {
                needs_patch = true;
            } else {
                params_serializer.append_pair(&key, &value);
            }
        }
        params_serializer.finish();
    }

    if parse.query_pairs().count() == 0 {
        parse.set_query(None);
    }

    if !needs_patch {
        info!("Youtube link doesn't need patching: {}", link);
        None
    } else {
        let patched = parse.to_string();
        info!("Youtube link patched: {}", patched);
        Some(patched)
    }
}

#[instrument(skip(_tg, message))]
async fn handle_editable_message(_tg: &mut Client, message: Message) -> Result<(), Whatever> {
    // telegram gives offsets in utf-16 code points, yikes
    let mut text = message.text().encode_utf16().collect::<Vec<_>>();

    let mut text_rewrites = Vec::new();
    let mut entity_rewrites = Vec::new();

    if let Some(entities) = message.fmt_entities() {
        for (entity_idx, entity) in entities.iter().enumerate() {
            match entity {
                MessageEntity::Url(url) => {
                    let url_content =
                        String::from_utf16(&text[url.offset as usize..][..url.length as usize])
                            .whatever_context("Converting url to utf-16 and back")?;

                    if let Some(patched_url) = check_link(&url_content) {
                        text_rewrites.push((
                            url.offset,
                            url.length,
                            patched_url.encode_utf16().collect::<Vec<_>>(),
                        ));
                    }
                }
                MessageEntity::TextUrl(url) => {
                    if let Some(patched_url) = check_link(&url.url) {
                        entity_rewrites.push((
                            entity_idx,
                            MessageEntity::TextUrl(MessageEntityTextUrl {
                                url: patched_url,
                                offset: url.offset,
                                length: url.length,
                            }),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    if text_rewrites.is_empty() && entity_rewrites.is_empty() {
        return Ok(());
    }

    let mut fmt_entities = message.fmt_entities().cloned();
    for (index, entity) in entity_rewrites {
        fmt_entities.as_mut().unwrap()[index] = entity;
    }

    for (offset, length, rewrite) in text_rewrites.into_iter().rev() {
        let length_delta = rewrite.len() as i32 - length;
        for entity in fmt_entities.as_mut().unwrap() {
            // yaaay
            let (entity_offset, entity_len) = match entity {
                MessageEntity::Bold(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Italic(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Underline(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Strike(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Code(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Pre(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::TextUrl(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Mention(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Hashtag(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Cashtag(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::BotCommand(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Url(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Email(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Phone(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::BankCard(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::MentionName(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Unknown(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::InputMessageEntityMentionName(entity) => {
                    (&mut entity.offset, &mut entity.length)
                }
                MessageEntity::Blockquote(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::Spoiler(entity) => (&mut entity.offset, &mut entity.length),
                MessageEntity::CustomEmoji(entity) => (&mut entity.offset, &mut entity.length),
            };

            // TODO: this is not entirely correct
            // probably need to handle a bit more corner cases & consider actual overlap of changed region with the entity
            if *entity_offset >= offset + length {
                *entity_offset += length_delta;
            } else if *entity_offset >= offset {
                *entity_len += length_delta;
            }
        }

        text.splice(offset as usize..offset as usize + length as usize, rewrite);
    }

    let text = String::from_utf16(&text).whatever_context("Converting text to utf-16 and back")?;

    let mut new_message = InputMessage::text(text);

    if let Some(fmt_entities) = fmt_entities {
        new_message = new_message.fmt_entities(fmt_entities);
    }

    if let Some(Media::WebPage(_)) = message.media() {
        new_message = new_message.link_preview(true);
    }

    if let Some(media) = message.media() {
        new_message = new_message.copy_media(&media);
    }

    message
        .edit(new_message)
        .await
        .whatever_context("Editing message")?;

    Ok(())
}

#[instrument(skip(tg))]
async fn handle_update(tg: &mut Client, update: Update) -> Result<(), Whatever> {
    match update {
        Update::NewMessage(message) if message.outgoing() => {
            handle_editable_message(tg, message).await?;
        }
        Update::NewMessage(message) if !message.outgoing() => {
            match message.chat() {
                Chat::Channel(channel) => {
                    if let Some(rights) = channel.admin_rights() {
                        if rights.edit_messages {
                            handle_editable_message(tg, message).await?;
                        }
                    }
                }
                Chat::User(user) => {
                    // this handles saved messages
                    if user.is_self() {
                        handle_editable_message(tg, message).await?;
                    }
                }
                _ => {}
            }
        }
        _ => {}
    };

    Ok(())
}

async fn handle_updates(mut tg: Client) -> Result<(), Whatever> {
    info!("Listening for updates...");

    while let Some(update) = tg
        .next_update()
        .await
        .whatever_context("Getting update from telegram")?
    {
        if let Err(e) = handle_update(&mut tg, update).await {
            error!("Error during update handling: {}", e);
        }
    }

    Ok(())
}

fn save_session(client: &Client, config: &config::Telegram) -> Result<(), Whatever> {
    if let Some(session_storage) = &config.session_storage {
        debug!("Saving session to {}", session_storage);
        std::fs::write(session_storage, client.session().save())
            .whatever_context("Saving session")?;
    }

    Ok(())
}

async fn save_session_periodic(client: &Client, config: &config::Telegram) -> Result<(), Whatever> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 5));

    loop {
        interval.tick().await;
        save_session(client, config)?;
    }
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), Whatever> {
    init_tracing::init_tracing().whatever_context("Setting up the opentelemetry exporter")?;

    let environment = std::env::var("ENVIRONMENT").whatever_context(
        "Please set ENVIRONMENT env var (probably you want to use either 'prod' or 'dev')",
    )?;

    let config =
        config::Config::load(&environment).whatever_context("Loading config has failed")?;

    info!("Resolved config: {:#?}", config);

    let client = connect_and_login(&config.telegram).await?;

    let me = client.get_me().await.whatever_context("Getting me")?;
    if me.is_bot() {
        info!("Signed in as bot @{}", me.username().unwrap_or_default());
    } else {
        info!(
            "Signed in as user {} {}",
            me.full_name(),
            me.username()
                .map(|u| format!("(@{})", u))
                .unwrap_or_default()
        );
    }

    tokio::select!(
        _ = tokio::signal::ctrl_c() => {
            info!("Got SIGINT; quitting early gracefully");
        }
        r = handle_updates(client.clone()) => {
            match r {
                Ok(_) => info!("Got disconnected from Telegram gracefully"),
                Err(e) => error!("Error during update handling: {}", e),
            }
        }
        r = save_session_periodic(&client, &config.telegram) => {
            match r {
                Ok(_) => unreachable!(),
                Err(e) => error!("Error during session saving: {}", e),
            }
        }
    );

    save_session(&client, &config.telegram)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::check_link;

    #[test]
    fn check_links() {
        assert_eq!(check_link("https://google.com"), None);
        assert_eq!(check_link("https://www.youtube.com/watch?v=123"), None);
        assert_eq!(
            check_link("https://www.youtube.com/watch?v=123&si=123"),
            Some("https://www.youtube.com/watch?v=123".to_string())
        );
        assert_eq!(
            check_link("https://youtu.be/LD6ePgLagcU?si=_cQB9sCsJ62lkPyW"),
            Some("https://youtu.be/LD6ePgLagcU".to_string())
        );
        assert_eq!(
            check_link("https://www.youtube.com/watch?v=nH5Ok7dNb9M"),
            None
        );
        assert_eq!(
            check_link("https://youtube.com/shorts/yt7a0WJmy8I?si=16F3eoZUJtn1f9Cy"),
            Some("https://youtube.com/shorts/yt7a0WJmy8I".to_string())
        );
    }
}
