package protocol

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	gethbridge "github.com/status-im/status-go/eth-node/bridge/geth"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/common"
	"github.com/status-im/status-go/protocol/protobuf"
	"github.com/status-im/status-go/protocol/tt"
	"github.com/status-im/status-go/waku"
)

func TestMessengerOrganisationsSuite(t *testing.T) {
	suite.Run(t, new(MessengerOrganisationsSuite))
}

type MessengerOrganisationsSuite struct {
	suite.Suite
	m          *Messenger        // main instance of Messenger
	privateKey *ecdsa.PrivateKey // private key for the main instance of Messenger
	// If one wants to send messages between different instances of Messenger,
	// a single Waku service should be shared.
	shh    types.Waku
	logger *zap.Logger
}

func (s *MessengerOrganisationsSuite) SetupTest() {
	s.logger = tt.MustCreateTestLogger()

	config := waku.DefaultConfig
	config.MinimumAcceptedPoW = 0
	shh := waku.New(&config, s.logger)
	s.shh = gethbridge.NewGethWakuWrapper(shh)
	s.Require().NoError(shh.Start(nil))

	s.m = s.newMessenger(s.shh)
	s.privateKey = s.m.identity
	s.Require().NoError(s.m.Start())
}

func (s *MessengerOrganisationsSuite) TearDownTest() {
	s.Require().NoError(s.m.Shutdown())
	_ = s.logger.Sync()
}

func (s *MessengerOrganisationsSuite) newMessengerWithOptions(shh types.Waku, privateKey *ecdsa.PrivateKey, options []Option) *Messenger {
	m, err := NewMessenger(
		privateKey,
		&testNode{shh: shh},
		uuid.New().String(),
		options...,
	)
	s.Require().NoError(err)

	err = m.Init()
	s.Require().NoError(err)

	return m
}

func (s *MessengerOrganisationsSuite) newMessengerWithKey(shh types.Waku, privateKey *ecdsa.PrivateKey) *Messenger {
	tmpFile, err := ioutil.TempFile("", "")
	s.Require().NoError(err)

	options := []Option{
		WithCustomLogger(s.logger),
		WithMessagesPersistenceEnabled(),
		WithDatabaseConfig(tmpFile.Name(), ""),
		WithDatasync(),
	}
	return s.newMessengerWithOptions(shh, privateKey, options)
}

func (s *MessengerOrganisationsSuite) newMessenger(shh types.Waku) *Messenger {
	privateKey, err := crypto.GenerateKey()
	s.Require().NoError(err)

	return s.newMessengerWithKey(s.shh, privateKey)
}

func (s *MessengerOrganisationsSuite) TestRetrieveOrganisation() {
	bob := s.m
	alice := s.newMessenger(s.shh)
	// start alice and enable sending push notifications
	s.Require().NoError(alice.Start())

	description := &protobuf.OrganisationDescription{
		Permissions: &protobuf.OrganisationPermissions{
			Access: protobuf.OrganisationPermissions_NO_MEMBERSHIP,
		},
		Identity: &protobuf.ChatIdentity{
			DisplayName: "status",
			Description: "status organisation description",
		},
	}

	organisation, err := bob.CreateOrganisation(description)
	s.Require().NoError(err)
	s.Require().NotNil(organisation)

	// Send an organisation message
	chat := CreateOneToOneChat(common.PubkeyToHex(&alice.identity.PublicKey), &alice.identity.PublicKey, s.m.transport)

	inputMessage := &common.Message{}
	inputMessage.ChatId = chat.ID
	inputMessage.Text = "some text"
	inputMessage.OrganisationID = organisation.IDString()

	err = s.m.SaveChat(&chat)
	s.NoError(err)
	_, err = s.m.SendChatMessage(context.Background(), inputMessage)
	s.NoError(err)

	var response *MessengerResponse
	// Pull message and make sure org is received
	err = tt.RetryWithBackOff(func() error {
		response, err = alice.RetrieveAll()
		if err != nil {
			return err
		}
		if len(response.Organisations) == 0 {
			return errors.New("organisation not received")
		}
		return nil
	})

	s.Require().NoError(err)
	organisations, err := alice.Organisations()
	s.Require().NoError(err)
	s.Require().Len(organisations, 1)
	s.Require().Len(response.Organisations, 1)
	s.Require().Len(response.Messages, 1)
	s.Require().Equal(organisation.IDString(), response.Messages[0].OrganisationID)
}
