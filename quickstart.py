import os.path
import base64

import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.message import EmailMessage

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

def get_credentials():
  creds = None
  # The file token.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
  if os.path.exists("token.json"):
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)
  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())
    else:
      flow = InstalledAppFlow.from_client_secrets_file(
          "credentials.json", SCOPES
      )
      creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open("token.json", "w") as token:
      token.write(creds.to_json())
  return creds


def gmail_send_message(from_email,to_email,subject,body):
  creds = get_credentials()

  try:
    service = build("gmail", "v1", credentials=creds)
    message = EmailMessage()

    message.set_content(body)

    message["To"] = to_email
    message["From"] = from_email
    message["Subject"] = subject

    # encoded message
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    create_message = {"raw": encoded_message}
    # pylint: disable=E1101
    send_message = (
        service.users()
        .messages()
        .send(userId="me", body=create_message)
        .execute()
    )
    print(f'Email has been sent with the following id: {send_message["id"]}')
  except HttpError as error:
    print(f"An error occurred: {error}")
    send_message = None
  return send_message

def main():
    print("Script to send an email from gmail in python")
    from_email = input("Enter your email address: ")
    to_email = input("Enter the receiver's email address: ")
    subject = input("Enter the subject of the email: ")
    body = input("Enter the body of the email:\n")
    gmail_send_message(from_email,to_email,subject,body)

if __name__ == "__main__":
  main()
