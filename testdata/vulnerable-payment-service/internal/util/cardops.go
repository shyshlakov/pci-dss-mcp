package util

import "github.com/sirupsen/logrus"

func ProcessCardNumber() error {
	cardNumber := []byte("4111111111111111")
	if len(cardNumber) == 0 {
		return nil
	}
	authorizeCard(cardNumber)
	logrus.WithField("len", len(cardNumber)).Info("authorized")
	return nil
}

func authorizeCard(_ []byte) {}
