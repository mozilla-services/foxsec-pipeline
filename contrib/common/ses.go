package common

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
)

const (
	EMAIL_CHAR_SET = "UTF-8"
)

type SESClient struct {
	sesClient              sesiface.SESAPI
	senderEmail            string
	defaultEscalationEmail string
}

//EscalationMailer formats and sends necessary emails for notifications
type EscalationMailer interface {
	SendEscalationEmail(alert *Alert) error
	Send911Email(caller string, msg string) error
	DefaultEscalationEmail() string
}

func NewSESClientFromConfig(config *Configuration) (*SESClient, error) {
	return NewSESClient(
		config.AwsRegion,
		config.AwsAccessKeyId,
		config.AwsSecretAccessKey,
		config.SesSenderEmail,
		config.DefaultEscalationEmail,
	)
}

func NewSESClient(region, accessKeyId, secretAccessKey, senderEmail, escalationEmail string) (*SESClient, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKeyId, secretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	return &SESClient{
		sesClient:              ses.New(sess),
		senderEmail:            senderEmail,
		defaultEscalationEmail: escalationEmail,
	}, nil
}

// SendEscalationEmail sends an email notification with an alert that needs to be escalated
func (sesc *SESClient) SendEscalationEmail(alert *Alert) error {
	subject := fmt.Sprintf("[foxsec-alert] Escalating alert - %s", alert.Summary)

	escalationEmail := alert.GetMetadata(ESCALATE_TO)
	if escalationEmail == "" {
		escalationEmail = sesc.defaultEscalationEmail
	}

	bodyMsg := alert.PrettyPrint()

	return sesc.SendEmail(escalationEmail, subject, bodyMsg)

}

// Send911Email sends an email notification to the default escalation email
// with a message from the slack slash command invocation
func (sesc *SESClient) Send911Email(caller string, msg string) error {
	subject := fmt.Sprintf("[foxsec] Secops 911 from %s via slack", caller)
	body := fmt.Sprintf("%s on slack raised a secops911 with the message: %s", caller, msg)
	escalationEmail := sesc.defaultEscalationEmail

	return sesc.SendEmail(escalationEmail, subject, body)
}

// SendEmail sends an email to email
func (sesc *SESClient) SendEmail(recipient string, subject string, bodyMsg string) error {
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(recipient),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String(EMAIL_CHAR_SET),
					Data:    aws.String(bodyMsg),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(EMAIL_CHAR_SET),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(sesc.senderEmail),
	}

	_, err := sesc.sesClient.SendEmail(input)
	if err != nil {
		return err
	}

	return nil
}

// DefaultEscalationEmail returns the default value to which emails are sent
func (sesc *SESClient) DefaultEscalationEmail() string {
	return sesc.defaultEscalationEmail
}
