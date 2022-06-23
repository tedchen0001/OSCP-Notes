# python3

import smtplib
from email.message import EmailMessage

def main():
    smtp_server = "192.168.0.100"
    smtp_port = 25 

    #username = ""
    #passowrd = ""

    msg = EmailMessage()

    password = "" 
    msg['From'] = "user1@test.com"
    # multiple recipients
    recipients = ['user2@test.com', 'user2@test.com', 'user3@test.com', 'user4@test.com', 'user5@test.com', 'user6@test.com', 'user7@test.com']
    msg['To'] = ", ".join(recipients)
    #msg['To'] = "user2@test.com"
    msg['Subject'] = "Hello!"

    message = "Hello!"

    msg.set_content(message)

    #server = smtplib.SMTP_SSL(smtp_server, smtp_port)
    server = smtplib.SMTP(smtp_server,smtp_port)

    # doesn't need authentication
    #server.login(username, passowrd)

    server.send_message(msg)

    server.quit()

    print("Mail sent successfully! %s" % (msg['To']))

if __name__ == "__main__":
    main()