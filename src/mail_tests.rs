//! Exercise the upgraded IMAP wire parser without sockets, credentials, or Apple data.
use super::*;
use std::{cell::RefCell, io::Cursor, rc::Rc};

struct Transcript {
    replies: Cursor<Vec<u8>>,
    writes: Rc<RefCell<Vec<u8>>>,
}

impl Read for Transcript {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.replies.read(bytes)
    }
}

impl Write for Transcript {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn client(replies: &str) -> (imap::Client<Transcript>, Rc<RefCell<Vec<u8>>>) {
    let writes = Rc::new(RefCell::new(Vec::new()));
    let stream = Transcript {
        replies: Cursor::new(replies.as_bytes().to_vec()),
        writes: writes.clone(),
    };
    let mut client = imap::Client::new(stream);
    client.read_greeting().unwrap();
    (client, writes)
}

#[test]
fn upgraded_imap_reads_messages_saves_drafts_and_keeps_uid_scope() {
    let raw = "To: alex@example.com\r\nSubject: Meeting\r\n\r\nPreparation notes.";
    let replies = format!(
        "* OK Test server\r\na1 OK LOGIN completed\r\n\
         * LIST (\\HasNoChildren) \"/\" \"Project Drafts\"\r\na2 OK LIST completed\r\n\
         * 2 EXISTS\r\n* OK [UIDVALIDITY 5] UIDs valid\r\na3 OK [READ-WRITE] SELECT completed\r\n\
         * SEARCH 7 42\r\na4 OK SEARCH completed\r\n\
         * 2 FETCH (UID 42 BODY[] {{{}}}\r\n{raw})\r\na5 OK FETCH completed\r\n\
         + Ready for literal\r\na6 OK [APPENDUID 5 43] APPEND completed\r\n\
         a7 OK STORE completed\r\n\
         a8 OK COPY completed\r\n\
         * 2 EXPUNGE\r\na9 OK UID EXPUNGE completed\r\n\
         * BYE Logging out\r\na10 OK LOGOUT completed\r\n",
        raw.len()
    );
    let (client, writes) = client(&replies);
    let mut session = client
        .login("simulation@example.com", "synthetic-password")
        .map_err(|(error, _)| error)
        .unwrap();
    let folders = session.list(Some(""), Some("*")).unwrap();
    assert_eq!(folders.iter().next().unwrap().name(), "Project Drafts");
    assert_eq!(session.select("Project Drafts").unwrap().exists, 2);
    let uids = session.uid_search("ALL").unwrap();
    assert_eq!(mail_page_ids(uids.into_iter().collect(), 0, 10), [42, 7]);
    let fetched = session.uid_fetch("42", "(UID BODY.PEEK[])").unwrap();
    let message = fetched.iter().next().unwrap();
    assert_eq!(message.uid, Some(42));
    assert_eq!(message.body().unwrap(), raw.as_bytes());
    let parsed = mailparse::parse_mail(message.body().unwrap()).unwrap();
    assert_eq!(mail_text_body(&parsed), "Preparation notes.");
    save_mail_draft(&mut session, raw.as_bytes()).unwrap();
    session.uid_store("42", "+FLAGS.SILENT (\\Seen)").unwrap();
    session.uid_copy("42", "Archive").unwrap();
    session.uid_expunge("42").unwrap();
    session.logout().unwrap();
    let commands = String::from_utf8(writes.borrow().clone()).unwrap();
    assert!(commands.contains("SELECT \"Project Drafts\"\r\n"));
    assert!(commands.contains("UID FETCH 42 (UID BODY.PEEK[])\r\n"));
    assert!(commands.contains(&format!(
        "APPEND \"Drafts\" (\\Draft) {{{}}}\r\n{raw}\r\n",
        raw.len()
    )));
    assert!(commands.contains("UID STORE 42 +FLAGS.SILENT (\\Seen)\r\n"));
    assert!(commands.contains("UID COPY 42 Archive\r\n"), "{commands}");
    assert!(commands.contains("UID EXPUNGE 42\r\n"));
    assert!(!commands.lines().any(|line| line.ends_with(" EXPUNGE")));
}

#[test]
fn rejected_draft_is_reported_without_repeating_the_write() {
    let (client, writes) =
        client("* OK Test server\r\na1 OK LOGIN completed\r\n+ Ready\r\na2 NO Mailbox full\r\n");
    let mut session = client
        .login("simulation@example.com", "synthetic-password")
        .map_err(|(error, _)| error)
        .unwrap();
    let error = save_mail_draft(&mut session, b"Subject: Test\r\n\r\nBody").unwrap_err();
    assert!(format!("{error:#}").contains("Mailbox full"));
    assert!(format!("{error:#}").contains("Could not save"));
    let commands = String::from_utf8(writes.borrow().clone()).unwrap();
    assert_eq!(commands.matches("APPEND").count(), 1);
}
