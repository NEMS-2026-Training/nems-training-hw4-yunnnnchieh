package detector

import (
	"github.com/free5gc/openapi/models"
)

var CurrentAuthProcedure AuthProcedureInfo

// Define every thing you want in this struct,
// so that you can use them in different message handler
type AuthProcedureInfo struct {
	SupiOrSuci         string
	Supi               string
	ServingNetworkName string
	AuthSubsData       models.AuthenticationSubscription
	Rand               string
	XresStar           string
	HxresStar          string
	Autn               string
	Kausf              string
	Kseaf              string
}
