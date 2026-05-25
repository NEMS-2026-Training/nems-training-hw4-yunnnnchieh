package detector

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/free5gc/UeauCommon"
	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/consumer"
	"github.com/free5gc/scp/logger"
)

const (
	ERR_MANDATORY_ABSENT = "mandatory type is absent"
	ERR_MISS_CONDITION   = "missing conditions"
	ERR_VALUE_INCORRECT  = "unexpected value is received"

	ausfURI = "http://127.0.0.9:8000"
	udmURI  = "http://127.0.0.3:8000"
	udrURI  = "http://127.0.0.4:8000"
)

func HandleAuth5gAkaComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.DetectorLog.Infof("Auth5gAkaComfirmRequest")
	updateConfirmationData := request.Body.(models.ConfirmationData)
	ConfirmationDataResponseID := request.Params["authCtxId"]

	// NOTE: The request from AMF is guaranteed to be correct

	targetNfUri := ausfURI

	response, problemDetails, err := consumer.SendAuth5gAkaConfirmRequest(targetNfUri, ConfirmationDataResponseID, &updateConfirmationData)

	if response != nil {
		checkConfirmationDataResponse(response)
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.DetectorLog.Infof("HandleUeAuthPostRequest")
	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)

	// NOTE: The request from AMF is guaranteed to be correct
	CurrentAuthProcedure.SupiOrSuci = updateAuthenticationInfo.SupiOrSuci
	CurrentAuthProcedure.ServingNetworkName = updateAuthenticationInfo.ServingNetworkName
	CurrentAuthProcedure.Supi = ""
	if strings.HasPrefix(updateAuthenticationInfo.SupiOrSuci, "suci-") {
		if supi, err := extractSupi(updateAuthenticationInfo.SupiOrSuci); err == nil {
			CurrentAuthProcedure.Supi = supi
		}
	} else {
		CurrentAuthProcedure.Supi = updateAuthenticationInfo.SupiOrSuci
	}

	targetNfUri := ausfURI

	response, respHeader, problemDetails, err := consumer.SendUeAuthPostRequest(targetNfUri, &updateAuthenticationInfo)

	if response != nil {
		checkUeAuthenticationCtx(response)
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusCreated, respHeader, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleGenerateAuthDataRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.DetectorLog.Infoln("Handle GenerateAuthDataRequest")

	authInfoRequest := request.Body.(models.AuthenticationInfoRequest)
	supiOrSuci := request.Params["supiOrSuci"]

	if authInfoRequest.ServingNetworkName == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoRequest.ServingNetworkName: %s", ERR_MANDATORY_ABSENT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.ServingNetworkName
	} else if authInfoRequest.ServingNetworkName != CurrentAuthProcedure.ServingNetworkName {
		logger.DetectorLog.Errorf("AuthenticationInfoRequest.ServingNetworkName: %s", ERR_VALUE_INCORRECT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.ServingNetworkName
	}

	targetNfUri := udmURI

	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)

	if response != nil {
		checkAuthenticationInfoResult(response, authInfoRequest.ServingNetworkName)
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleQueryAuthSubsData(request *http_wrapper.Request) *http_wrapper.Response {
	logger.DetectorLog.Infof("Handle QueryAuthSubsData")

	ueId := request.Params["ueId"]

	targetNfUri := udrURI

	response, problemDetails, err := consumer.SendAuthSubsDataGet(targetNfUri, ueId)

	// NOTE: The response from UDR is guaranteed to be correct
	if response != nil {
		CurrentAuthProcedure.AuthSubsData = *response
		if CurrentAuthProcedure.Supi == "" {
			CurrentAuthProcedure.Supi = ueId
		}
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func checkAuthenticationInfoResult(response *models.AuthenticationInfoResult, servingNetworkName string) {
	if response.AuthType == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthType: %s", ERR_MANDATORY_ABSENT)
		response.AuthType = models.AuthType__5_G_AKA
	} else if response.AuthType != models.AuthType__5_G_AKA {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthType: %s", ERR_VALUE_INCORRECT)
		response.AuthType = models.AuthType__5_G_AKA
	}

	if response.AuthenticationVector == nil {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthenticationVector: %s", ERR_MANDATORY_ABSENT)
		response.AuthenticationVector = &models.AuthenticationVector{}
	}
	av := response.AuthenticationVector
	if av.AvType == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthenticationVector.AvType: %s", ERR_MANDATORY_ABSENT)
		av.AvType = models.AvType__5_G_HE_AKA
	} else if av.AvType != models.AvType__5_G_HE_AKA {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthenticationVector.AvType: %s", ERR_VALUE_INCORRECT)
		av.AvType = models.AvType__5_G_HE_AKA
	}
	if av.Rand == "" {
		logger.DetectorLog.Errorf("AuthenticationInfoResult.AuthenticationVector.Rand: %s", ERR_MANDATORY_ABSENT)
	}
	if av.Rand == "" {
		return
	}

	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, av.Rand)
	randBytes, _ := hex.DecodeString(av.Rand)
	key := append(append([]byte{}, ck...), ik...)
	xresStar := retrieveXresStar(key, UeauCommon.FC_FOR_RES_STAR_XRES_STAR_DERIVATION,
		[]byte(servingNetworkName), randBytes, xres)
	kausf := retrieve5GAkaKausf(key, UeauCommon.FC_FOR_KAUSF_DERIVATION,
		[]byte(servingNetworkName), sqnXorAk)
	kseaf := retrieveKseaf(kausf, UeauCommon.FC_FOR_KSEAF_DERIVATION, []byte(servingNetworkName))
	hxresStar := retrieveHxresStar(append(randBytes, xresStar...))

	CurrentAuthProcedure.Rand = av.Rand
	CurrentAuthProcedure.XresStar = hex.EncodeToString(xresStar)
	CurrentAuthProcedure.HxresStar = hex.EncodeToString(hxresStar)
	CurrentAuthProcedure.Autn = hex.EncodeToString(autn)
	CurrentAuthProcedure.Kausf = hex.EncodeToString(kausf)
	CurrentAuthProcedure.Kseaf = hex.EncodeToString(kseaf)

	checkString("AuthenticationInfoResult.AuthenticationVector.XresStar", &av.XresStar, CurrentAuthProcedure.XresStar, true)
	checkString("AuthenticationInfoResult.AuthenticationVector.Autn", &av.Autn, CurrentAuthProcedure.Autn, true)
	checkString("AuthenticationInfoResult.AuthenticationVector.Kausf", &av.Kausf, CurrentAuthProcedure.Kausf, true)
}

func checkUeAuthenticationCtx(response *models.UeAuthenticationCtx) {
	if response.AuthType == "" {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.AuthType: %s", ERR_MANDATORY_ABSENT)
		response.AuthType = models.AuthType__5_G_AKA
	} else if response.AuthType != models.AuthType__5_G_AKA {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.AuthType: %s", ERR_VALUE_INCORRECT)
		response.AuthType = models.AuthType__5_G_AKA
	}

	if response.Var5gAuthData == nil {
		logger.DetectorLog.Errorf("UeAuthenticationCtx.5gAuthData: %s", ERR_MISS_CONDITION)
		response.Var5gAuthData = models.Av5gAka{}
	}
	av := av5gAkaFromInterface(response.Var5gAuthData)
	checkString("UeAuthenticationCtx.5gAuthData.Rand", &av.Rand, CurrentAuthProcedure.Rand, true)
	checkString("UeAuthenticationCtx.5gAuthData.HxresStar", &av.HxresStar, CurrentAuthProcedure.HxresStar, true)
	checkString("UeAuthenticationCtx.5gAuthData.Autn", &av.Autn, CurrentAuthProcedure.Autn, true)
	response.Var5gAuthData = av
}

func checkConfirmationDataResponse(response *models.ConfirmationDataResponse) {
	if response.AuthResult == models.AuthResult_SUCCESS {
		checkString("ConfirmationDataResponse.Supi", &response.Supi, CurrentAuthProcedure.Supi, false)
		checkString("ConfirmationDataResponse.Kseaf", &response.Kseaf, CurrentAuthProcedure.Kseaf, false)
	}
}

func checkString(typeName string, got *string, expected string, mandatory bool) {
	if *got == "" {
		if mandatory {
			logger.DetectorLog.Errorf("%s: %s", typeName, ERR_MANDATORY_ABSENT)
		} else {
			logger.DetectorLog.Errorf("%s: %s", typeName, ERR_MISS_CONDITION)
		}
		*got = expected
	} else if expected != "" && !strings.EqualFold(*got, expected) {
		logger.DetectorLog.Errorf("%s: %s", typeName, ERR_VALUE_INCORRECT)
		*got = expected
	}
}

func av5gAkaFromInterface(data interface{}) models.Av5gAka {
	switch value := data.(type) {
	case models.Av5gAka:
		return value
	case *models.Av5gAka:
		if value != nil {
			return *value
		}
	case map[string]interface{}:
		return models.Av5gAka{
			Rand:      stringFromMap(value, "rand"),
			HxresStar: stringFromMap(value, "hxresStar"),
			Autn:      stringFromMap(value, "autn"),
		}
	}
	return models.Av5gAka{}
}

func stringFromMap(values map[string]interface{}, key string) string {
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}
