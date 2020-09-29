package organisations

import (
	"github.com/status-im/status-go/protocol/protobuf"
)

func validateOrganisationChat(desc *protobuf.OrganisationDescription, chat *protobuf.OrganisationChat) error {
	if chat == nil {
		return ErrInvalidOrganisationDescription
	}
	if chat.Permissions == nil {
		return ErrInvalidOrganisationDescription
	}
	if chat.Permissions.Access == protobuf.OrganisationPermissions_UNKNOWN_ACCESS {
		return ErrInvalidOrganisationDescription
	}

	for pk, _ := range chat.Members {
		if desc.Members == nil {
			return ErrInvalidOrganisationDescription
		}
		// Check member is in the org as well
		if _, ok := desc.Members[pk]; !ok {
			return ErrInvalidOrganisationDescription
		}
	}

	return nil
}

func ValidateOrganisationDescription(desc *protobuf.OrganisationDescription) error {
	if desc == nil {
		return ErrInvalidOrganisationDescription
	}
	if desc.Permissions == nil {
		return ErrInvalidOrganisationDescription
	}
	if desc.Permissions.Access == protobuf.OrganisationPermissions_UNKNOWN_ACCESS {
		return ErrInvalidOrganisationDescription
	}

	for _, chat := range desc.Chats {
		if err := validateOrganisationChat(desc, chat); err != nil {
			return err
		}
	}

	return nil
}
