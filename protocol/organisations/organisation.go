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
	ID                      *ecdsa.PublicKey
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

type OrganisationChatChanges struct {
	MembersAdded   map[string]*protobuf.OrganisationMember
	MembersRemoved map[string]*protobuf.OrganisationMember
}

type OrganisationChanges struct {
	MembersAdded   map[string]*protobuf.OrganisationMember
	MembersRemoved map[string]*protobuf.OrganisationMember

	ChatsRemoved  map[string]*protobuf.OrganisationChat
	ChatsAdded    map[string]*protobuf.OrganisationChat
	ChatsModified map[string]*OrganisationChatChanges
}

func emptyOrganisationChanges() *OrganisationChanges {
	return &OrganisationChanges{
		MembersAdded:   make(map[string]*protobuf.OrganisationMember),
		MembersRemoved: make(map[string]*protobuf.OrganisationMember),

		ChatsRemoved:  make(map[string]*protobuf.OrganisationChat),
		ChatsAdded:    make(map[string]*protobuf.OrganisationChat),
		ChatsModified: make(map[string]*OrganisationChatChanges),
	}
}

func (o *Organisation) HandleOrganisationDescription(signer *ecdsa.PublicKey, description *protobuf.OrganisationDescription) (*OrganisationChanges, error) {
	// TOOD: validate signer

	err := ValidateOrganisationDescription(description)
	if err != nil {
		return nil, err
	}

	response := emptyOrganisationChanges()

	if description.Clock <= o.config.OrganisationDescription.Clock {
		return response, nil
	}

	// Check for new members at the org level
	for pk, member := range description.Members {
		if _, ok := o.config.OrganisationDescription.Members[pk]; !ok {
			if response.MembersAdded == nil {
				response.MembersAdded = make(map[string]*protobuf.OrganisationMember)
			}
			response.MembersAdded[pk] = member
		}
	}

	// Check for removed members at the org level
	for pk, member := range o.config.OrganisationDescription.Members {
		if _, ok := description.Members[pk]; !ok {
			if response.MembersRemoved == nil {
				response.MembersRemoved = make(map[string]*protobuf.OrganisationMember)
			}
			response.MembersRemoved[pk] = member
		}
	}

	// check for removed chats
	for chatID, chat := range o.config.OrganisationDescription.Chats {
		if description.Chats == nil {
			description.Chats = make(map[string]*protobuf.OrganisationChat)
		}
		if _, ok := description.Chats[chatID]; !ok {
			if response.ChatsRemoved == nil {
				response.ChatsRemoved = make(map[string]*protobuf.OrganisationChat)
			}

			response.ChatsRemoved[chatID] = chat
		}
	}

	for chatID, chat := range description.Chats {
		if o.config.OrganisationDescription.Chats == nil {
			o.config.OrganisationDescription.Chats = make(map[string]*protobuf.OrganisationChat)
		}
		if _, ok := o.config.OrganisationDescription.Chats[chatID]; !ok {
			if response.ChatsAdded == nil {
				response.ChatsAdded = make(map[string]*protobuf.OrganisationChat)
			}

			response.ChatsAdded[chatID] = chat
		} else {
			// Check for members added
			for pk, member := range description.Chats[chatID].Members {
				if _, ok := o.config.OrganisationDescription.Chats[chatID].Members[pk]; !ok {
					if response.ChatsModified[chatID] == nil {
						response.ChatsModified[chatID] = &OrganisationChatChanges{
							MembersAdded:   make(map[string]*protobuf.OrganisationMember),
							MembersRemoved: make(map[string]*protobuf.OrganisationMember),
						}
					}

					response.ChatsModified[chatID].MembersAdded[pk] = member
				}
			}

			// check for members removed
			for pk, member := range o.config.OrganisationDescription.Chats[chatID].Members {
				if _, ok := description.Chats[chatID].Members[pk]; !ok {
					if response.ChatsModified[chatID] == nil {
						response.ChatsModified[chatID] = &OrganisationChatChanges{
							MembersAdded:   make(map[string]*protobuf.OrganisationMember),
							MembersRemoved: make(map[string]*protobuf.OrganisationMember),
						}
					}

					response.ChatsModified[chatID].MembersRemoved[pk] = member
				}
			}
		}
	}

	o.config.OrganisationDescription = description

	return response, nil
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
	chat, ok := o.config.OrganisationDescription.Chats[request.ChatId]

	if !ok {
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
		OrganisationId: crypto.CompressPubkey(o.ID),
		MemberId:       crypto.CompressPubkey(key),
		ChatId:         chatID,
		Clock:          o.config.OrganisationDescription.Clock,
	}
	marshaledGrant, err := proto.Marshal(grant)
	if err != nil {
		return nil, err
	}

	signatureMaterial := crypto.Keccak256(marshaledGrant)

	return crypto.Sign(signatureMaterial, o.config.PrivateKey)
}
