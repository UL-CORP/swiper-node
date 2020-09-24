package organisations

import (
	"crypto/ecdsa"
	"sync"

	"github.com/golang/protobuf/proto"

	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/protocol/protobuf"
)

type Config struct {
	PrivateKey              *ecdsa.PrivateKey
	OrganisationDescription *protobuf.OrganisationDescription
	ID                      []byte
}

type Organisation struct {
	ID       *ecdsa.PublicKey
	Identity *protobuf.ChatMessageIdentity

	config       *Config
	membersMap   map[string]bool
	membersMapMU sync.Mutex
}

func New(config Config) *Organisation {
	organisation := &Organisation{config: &config}
	organisation.initialize()
	return organisation
}

func (o *Organisation) initialize() {
	o.membersMapMU.Lock()
	defer o.membersMapMU.Unlock()
	o.membersMap = make(map[string]bool)
	if o.config.OrganisationDescription == nil {
		o.config.OrganisationDescription = &protobuf.OrganisationDescription{}

	}
}

func (o *Organisation) AddMember(key *ecdsa.PublicKey) *protobuf.OrganisationDescription {

	return nil
}

func (o *Organisation) HasMember(key string) bool {
	o.membersMapMU.Lock()
	defer o.membersMapMU.Unlock()
	return o.membersMap[key]
}

// HandleRequestJoin handles a request, checks that the right permissions are applied and returns an OrganisationRequestJoinResponse
func (o *Organisation) HandleRequestJoin(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {
	// If we are not admin, fuggetaboutit
	if !o.IsAdmin() {
		return ErrNotAdmin
	}

	// If the org is ens name only, then reject if not present
	if o.config.OrganisationDescription.Permissions.EnsOnly && len(request.EnsName) == 0 {
		return ErrCantRequestAccess
	}

	if len(request.ChatId) != 0 {
		return o.handleRequestJoinWithChatID(signer, request)
	}

	return o.handleRequestJoinWithoutChatID(signer, request)
}

func (o *Organisation) IsAdmin() bool {
	return o.config.PrivateKey != nil
}

func (o *Organisation) handleRequestJoinWithChatID(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {
	var chat *protobuf.OrganisationChat
	for _, c := range o.config.OrganisationDescription.Chats {
		if c.ChatId == request.ChatId {
			chat = c
			break
		}
	}
	if chat == nil {
		return ErrChatNotFound
	}

	// If chat is no permissions, access should not have been requested
	if chat.Permissions.Access != protobuf.OrganisationPermissions_ON_REQUEST {
		return ErrCantRequestAccess
	}

	if chat.Permissions.EnsOnly && len(request.EnsName) == 0 {
		return ErrCantRequestAccess
	}

	return nil
}

func (o *Organisation) handleRequestJoinWithoutChatID(signer *ecdsa.PublicKey, request *protobuf.OrganisationRequestJoin) error {

	// If they want access to the org only, check that the org is ON_REQUEST
	if o.config.OrganisationDescription.Permissions.Access != protobuf.OrganisationPermissions_ON_REQUEST {
		return ErrCantRequestAccess
	}

	return nil
}

func (o *Organisation) buildGrant(key *ecdsa.PublicKey, chatID string) ([]byte, error) {
	grant := &protobuf.Grant{
		OrganisationId: o.config.ID,
		MemberId:       crypto.CompressPubkey(key),
		ChatId:         chatID,
		Clock:          o.lastClockValue(),
	}
	marshaledGrant, err := proto.Marshal(grant)
	if err != nil {
		return nil, err
	}

	signatureMaterial := crypto.Keccak256(marshaledGrant)

	return crypto.Sign(signatureMaterial, o.config.PrivateKey)
}

func (o *Organisation) lastClockValue() uint64 {
	return 0
}
