package organisations

import "errors"

var ErrChatNotFound = errors.New("chat not found")
var ErrOrgNotFound = errors.New("organisation not found")
var ErrChatAlreadyExists = errors.New("chat already exists")
var ErrCantRequestAccess = errors.New("can't request access")
var ErrInvalidOrganisationDescription = errors.New("invalid organisation description")
var ErrInvalidOrganisationDescriptionNoOrgPermissions = errors.New("invalid organisation description no org permissions")
var ErrInvalidOrganisationDescriptionNoChatPermissions = errors.New("invalid organisation description no chat permissions")
var ErrInvalidOrganisationDescriptionUnknownChatAccess = errors.New("invalid organisation description unknown chat access")
var ErrInvalidOrganisationDescriptionUnknownOrgAccess = errors.New("invalid organisation description unknown org access")
var ErrInvalidOrganisationDescriptionMemberInChatButNotInOrg = errors.New("invalid organisation description member in chat but not in org")
var ErrNotAdmin = errors.New("no admin privileges for this organisation")
var ErrInvalidGrant = errors.New("invalid grant")
var ErrNotAuthorized = errors.New("not authorized")
var ErrInvalidMessage = errors.New("invalid organisation description message")
