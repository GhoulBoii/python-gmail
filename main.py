import base64
import os
import time
from email.message import EmailMessage
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError

# Define the scopes required for the Gmail API
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]


def get_credentials() -> Credentials:
    """Gets user credentials for Gmail API."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def build_service() -> Optional[Resource]:
    """Builds and returns a Gmail API service object."""
    try:
        creds = get_credentials()
        service = build("gmail", "v1", credentials=creds)
        return service
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Error building the Gmail service: {error}")


def get_label_id(service: Resource, label_name: str) -> Optional[str]:
    """Fetches the ID of a label given its name."""
    try:
        labels = service.users().labels().list(userId="me").execute()
        for label in labels["labels"]:
            if label["name"] == label_name:
                return label["id"]
        return None
    except Exception as error:
        print(f"Error: {error}")
        return None


def create_label(service: Resource, label_name: str) -> None:
    """Creates a new label in the user's Gmail account."""
    try:
        label_id = get_label_id(service, label_name)
        label_body = {"addLabelIds": [label_id]}
        service.users().labels().create(userId="me", body=label_body).execute()
    except HttpError:
        print("Invalid label name or label already exists.")


def add_label(service: Resource, message_id: str, label_name: str) -> None:
    """Adds a label to a message."""
    try:
        label_id = get_label_id(service, label_name)
        labels_to_add = {"addLabelIds": [label_id]}

        service.users().messages().modify(
            userId="me", id=message_id, body=labels_to_add
        ).execute()
    except HttpError as error:
        print(f"Error adding label: {error}")


def get_thread_id(service: Resource, message_id: str) -> Optional[str]:
    """Fetches the thread ID for a given message."""
    try:
        message = service.users().messages().get(userId="me", id=message_id).execute()
        return message.get("threadId")
    except HttpError as error:
        print(f"Error getting thread ID: {error}")
        return None


def decode_body(message: dict) -> str:
    """Decodes the body of a message."""
    body = ""
    try:
        if "data" in message["payload"]["body"]:
            body = base64.urlsafe_b64decode(message["payload"]["body"]["data"]).decode(
                "utf-8"
            )
        elif "parts" in message["payload"]:
            for part in message["payload"]["parts"]:
                body += base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    except KeyError as e:
        print(f"Error decoding body: {e}")
    return body


def check_email_bounced_status(service: Resource, thread_id: str) -> None:
    """Checks if an email has bounced back."""
    time.sleep(2)
    try:
        messages = (
            service.users()
            .messages()
            .list(userId="me", q="from:mailer-daemon@googlemail.com")
            .execute()
            .get("messages", [])
        )
        for msg in messages:
            if msg["threadId"] == thread_id:
                raise Exception("Email bounced back. Check email addresses again.")
    except HttpError as error:
        print(f"Error checking email bounce status: {error}")


def send_message(
    service: Resource,
    from_email: str,
    to_email: str,
    subject: str,
    body: str,
    html_code: str,
) -> Optional[dict]:
    """Sends an email with the specified details."""
    try:
        message = EmailMessage()
        message.set_content(body + html_code, subtype="html")
        message["To"] = to_email
        message["From"] = from_email
        message["Subject"] = subject
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {"raw": encoded_message}
        sent_message = (
            service.users().messages().send(userId="me", body=create_message).execute()
        )
        check_email_bounced_status(service, sent_message["threadId"])
        return sent_message
    except HttpError as error:
        print(f"Error sending message: {error}")
        return None


def get_messages(service: Resource, message_no: int) -> Optional[Tuple[str, str, str]]:
    """Fetches a specified number of recent messages."""
    try:
        result = (
            service.users()
            .messages()
            .list(maxResults=message_no, userId="me")
            .execute()
        )
        messages = result.get("messages", [])
        for msg in messages:
            txt = service.users().messages().get(userId="me", id=msg["id"]).execute()
            payload = txt["payload"]
            headers = payload["headers"]
            subject, sender = "", ""
            for d in headers:
                if d["name"] == "Subject":
                    subject = d["value"]
                if d["name"] == "From":
                    sender = d["value"]
            parts = payload.get("parts", [])[0]
            data = parts["body"]["data"]
            data = data.replace("-", "+").replace("_", "/")
            decoded_data = base64.b64decode(data)
            soup = BeautifulSoup(decoded_data, "lxml")
            body = soup.body()
            return subject, sender, str(body)
    except HttpError as error:
        print(f"Error fetching messages: {error}")
        return None


def get_emails_from_thread(service: Resource, thread_id: str) -> List[dict]:
    """Fetches all emails in a specified thread."""
    try:
        emails = []
        thread = service.users().threads().get(userId="me", id=thread_id).execute()
        messages = thread.get("messages", [])
        for message in messages:
            if len(messages) > 1:
                subject, body = "", ""
                headers = message["payload"]["headers"]
                for header in headers:
                    if header["name"] == "Subject":
                        subject = header["value"]
                body = decode_body(message)
                emails.append({"subject": subject, "body": body})
        return emails
    except HttpError as error:
        print(f"Error fetching emails from thread: {error}")
        return []


def get_threads(
    service: Resource, label_name: Optional[str], to_email: str
) -> List[dict]:
    """Fetches threads based on label and recipient email."""
    try:
        result = []
        label_id = get_label_id(service, label_name) if label_name else "INBOX"
        threads = (
            service.users()
            .threads()
            .list(maxResults=100, userId="me", q=f"to:{to_email}", labelIds=[label_id])
            .execute()
            .get("threads", [])
        )
        for thread in threads:
            thread_id = thread["id"]
            emails = get_emails_from_thread(service, thread_id)
            result.extend(emails)
        return result
    except HttpError as error:
        print(f"Error fetching threads: {error}")
        return []


def main() -> None:
    service = build_service()

    print("Python Script to Interact with Gmail")
    print("Would you like to: ")
    print("1) Send email")
    print("2) See your inbox")
    print("3) Get your recent threads")
    print("4) Create label")
    choice = int(input("Enter your choice: "))

    if choice == 1:
        from_email = input("Enter your email address: ")
        to_email = input("Enter the receiver's email address: ")
        subject = input("Enter the subject of the email: ")
        body = input("Enter the body of the email:\n")
        html_code = input("Enter any HTML code: ")
        send_message(service, from_email, to_email, subject, body, html_code)
    elif choice == 2:
        message_no = int(
            input(
                "Enter the number of messages to display from your inbox (latest first): "
            )
        )
        messages = get_messages(service, message_no)
        if messages:
            print("\033[1;33;40mSubject: ", messages[0])
            print("\033[1;33;40mFrom: ", messages[1])
            print("Message: ", messages[2])
            print("-" * 50)
    elif choice == 3:
        label_name = input("Enter the name of the label (or leave blank for INBOX): ")
        to_email = input("Enter the recipient email address: ")
        threads = get_threads(service, label_name, to_email)
        for email in threads:
            print(f"Subject: {email['subject']}\nBody: {email['body']}\n{'-'*50}")
    elif choice == 4:
        label_name = input("Enter the name of the label: ")
        create_label(service, label_name)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
