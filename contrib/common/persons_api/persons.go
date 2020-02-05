// To parse and unparse this JSON data, add this code to your project and do:
//
//    person, err := UnmarshalPerson(bytes)
//    bytes, err = person.Marshal()

package persons_api

import "encoding/json"

func UnmarshalPerson(data []byte) (Person, error) {
	var r Person
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *Person) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

type Person struct {
	AccessInformation AccessInformationValuesArray    `json:"access_information"`
	Active            StandardAttributeBoolean        `json:"active"`
	AlternativeName   StandardAttributeString         `json:"alternative_name"`
	Created           StandardAttributeString         `json:"created"`
	Description       StandardAttributeString         `json:"description"`
	FirstName         StandardAttributeString         `json:"first_name"`
	FunTitle          StandardAttributeString         `json:"fun_title"`
	Identities        IdentitiesAttributesValuesArray `json:"identities"`
	Languages         StandardAttributeValues         `json:"languages"`
	LastModified      StandardAttributeString         `json:"last_modified"`
	LastName          StandardAttributeString         `json:"last_name"`
	Location          StandardAttributeString         `json:"location"`
	LoginMethod       StandardAttributeString         `json:"login_method"`
	PGPPublicKeys     StandardAttributeValues         `json:"pgp_public_keys"`
	PhoneNumbers      StandardAttributeValues         `json:"phone_numbers"`
	Picture           StandardAttributeString         `json:"picture"`
	PrimaryEmail      StandardAttributeString         `json:"primary_email"`
	PrimaryUsername   StandardAttributeString         `json:"primary_username"`
	Pronouns          StandardAttributeString         `json:"pronouns"`
	Schema            string                          `json:"schema"`
	SSHPublicKeys     StandardAttributeValues         `json:"ssh_public_keys"`
	StaffInformation  StaffInformationValuesArray     `json:"staff_information"`
	Tags              StandardAttributeValues         `json:"tags"`
	Timezone          StandardAttributeString         `json:"timezone"`
	Uris              StandardAttributeValues         `json:"uris"`
	UserID            StandardAttributeString         `json:"user_id"`
	Usernames         StandardAttributeValues         `json:"usernames"`
	UUID              StandardAttributeString         `json:"uuid"`
}

type AccessInformationValuesArray struct {
	AccessProvider AccessProviderAttribute `json:"access_provider"`
	Hris           HrisAttribute           `json:"hris"`
	LDAP           LDAPAttribute           `json:"ldap"`
	Mozilliansorg  MozilliansorgAttribute  `json:"mozilliansorg"`
}

type AccessProviderAttribute struct {
	Metadata  AccessProviderMetadata `json:"metadata"`
	Signature Signature              `json:"signature"`
	Values    map[string]interface{} `json:"values"`
}

type AccessProviderMetadata struct {
	Display        interface{}    `json:"display"`
	Classification Classification `json:"classification"`
	Created        string         `json:"created"`
	LastModified   string         `json:"last_modified"`
	Verified       bool           `json:"verified"`
}

type Signature struct {
	Additional []PublisherLax `json:"additional"`
	Publisher  Publisher      `json:"publisher"`
}

type PublisherLax struct {
	Alg   Alg     `json:"alg"`
	Name  *string `json:"name"`
	Typ   Typ     `json:"typ"`
	Value string  `json:"value"`
}

type Publisher struct {
	Alg   Alg                `json:"alg"`
	Name  PublisherAuthority `json:"name"`
	Typ   Typ                `json:"typ"`
	Value string             `json:"value"`
}

type HrisAttribute struct {
	Metadata  Metadata               `json:"metadata"`
	Signature Signature              `json:"signature"`
	Values    map[string]interface{} `json:"values"`
}

type LDAPAttribute struct {
	Metadata  Metadata               `json:"metadata"`
	Signature Signature              `json:"signature"`
	Values    map[string]interface{} `json:"values"`
}

type MozilliansorgAttribute struct {
	Metadata  Metadata               `json:"metadata"`
	Signature Signature              `json:"signature"`
	Values    map[string]interface{} `json:"values"`
}

type StandardAttributeString struct {
	Metadata  Metadata  `json:"metadata"`
	Signature Signature `json:"signature"`
	Value     string    `json:"value"`
}

type StandardAttributeBoolean struct {
	Metadata  Metadata  `json:"metadata"`
	Signature Signature `json:"signature"`
	Value     bool      `json:"value"`
}

type Metadata struct {
	Classification Classification  `json:"classification"`
	Created        string          `json:"created"`
	Display        DinoParkDisplay `json:"display"`
	LastModified   string          `json:"last_modified"`
	Verified       bool            `json:"verified"`
}

type IdentitiesAttributesValuesArray struct {
	BugzillaMozillaOrgID           *StandardAttributeString `json:"bugzilla_mozilla_org_id,omitempty"`
	BugzillaMozillaOrgPrimaryEmail *StandardAttributeString `json:"bugzilla_mozilla_org_primary_email,omitempty"`
	Custom1_PrimaryEmail           *StandardAttributeString `json:"custom_1_primary_email,omitempty"`
	Custom2_PrimaryEmail           *StandardAttributeString `json:"custom_2_primary_email,omitempty"`
	Custom3_PrimaryEmail           *StandardAttributeString `json:"custom_3_primary_email,omitempty"`
	FirefoxAccountsID              *StandardAttributeString `json:"firefox_accounts_id,omitempty"`
	FirefoxAccountsPrimaryEmail    *StandardAttributeString `json:"firefox_accounts_primary_email,omitempty"`
	GithubIDV3                     *StandardAttributeString `json:"github_id_v3,omitempty"`
	GithubIDV4                     *StandardAttributeString `json:"github_id_v4,omitempty"`
	GithubPrimaryEmail             *StandardAttributeString `json:"github_primary_email,omitempty"`
	GoogleOauth2ID                 *StandardAttributeString `json:"google_oauth2_id,omitempty"`
	GooglePrimaryEmail             *StandardAttributeString `json:"google_primary_email,omitempty"`
	MozillaLDAPID                  *StandardAttributeString `json:"mozilla_ldap_id,omitempty"`
	MozillaLDAPPrimaryEmail        *StandardAttributeString `json:"mozilla_ldap_primary_email,omitempty"`
	MozillaPOSIXID                 *StandardAttributeString `json:"mozilla_posix_id,omitempty"`
	MozilliansorgID                *StandardAttributeString `json:"mozilliansorg_id,omitempty"`
}

type StandardAttributeValues struct {
	Metadata  Metadata    `json:"metadata"`
	Signature Signature   `json:"signature"`
	Values    interface{} `json:"values"`
}

type StaffInformationValuesArray struct {
	CostCenter     StandardAttributeString  `json:"cost_center"`
	Director       StandardAttributeBoolean `json:"director"`
	Manager        StandardAttributeBoolean `json:"manager"`
	OfficeLocation StandardAttributeString  `json:"office_location"`
	Staff          StandardAttributeBoolean `json:"staff"`
	Team           StandardAttributeString  `json:"team"`
	Title          StandardAttributeString  `json:"title"`
	WorkerType     StandardAttributeString  `json:"worker_type"`
	WprDeskNumber  StandardAttributeString  `json:"wpr_desk_number"`
}

type Classification string

const (
	WORKGROUPCONFIDENTIALSTAFFONLY Classification = "WORKGROUP CONFIDENTIAL: STAFF ONLY"
	WORKGROUPCONFIDENTIAL          Classification = "WORKGROUP CONFIDENTIAL"
	IndividualConfidential         Classification = "INDIVIDUAL CONFIDENTIAL"
	MozillaConfidential            Classification = "MOZILLA CONFIDENTIAL"
	PUBLIC                         Classification = "PUBLIC"
)

type Alg string

const (
	Ed25519 Alg = "ED25519"
	Hs256   Alg = "HS256"
	RSA     Alg = "RSA"
	Rs256   Alg = "RS256"
)

type Typ string

const (
	Jws Typ = "JWS"
	PGP Typ = "PGP"
)

type PublisherAuthority string

const (
	AccessProvider PublisherAuthority = "access_provider"
	Cis            PublisherAuthority = "cis"
	Hris           PublisherAuthority = "hris"
	LDAP           PublisherAuthority = "ldap"
	Mozilliansorg  PublisherAuthority = "mozilliansorg"
)

type DinoParkDisplay string

const (
	Authenticated DinoParkDisplay = "authenticated"
	Ndaed         DinoParkDisplay = "ndaed"
	Private       DinoParkDisplay = "private"
	Staff         DinoParkDisplay = "staff"
	Vouched       DinoParkDisplay = "vouched"
	Public        DinoParkDisplay = "public"
)
