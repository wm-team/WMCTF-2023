package common

import (
	"crypto/tls"
	"net/smtp"
)

var (
	From     = "WMCTF2023@wm-team.cn"
	Password = "J9oMvqdJs5DNLcha"
)

func SendEmail(to, subject, body string) error {
	smtpHost := "smtp.feishu.cn"
	smtpPort := "465"

	msg := "From: " + From + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n" +
		"\n" +
		body

	auth := smtp.PlainAuth("", From, Password, smtpHost)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpHost,
	}

	conn, err := tls.Dial("tcp", smtpHost+":"+smtpPort, tlsConfig)
	if err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return err
	}

	if err := client.Auth(auth); err != nil {
		return err
	}

	if err := client.Mail(From); err != nil {
		return err
	}

	if err := client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(msg))
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	client.Quit()

	return nil
}
