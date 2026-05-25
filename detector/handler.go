package detector

import (
	"net/http"
	"strings"

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

	// TODO: Check IEs in response body is correct

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

	// TODO: Check IEs in response body is correct

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

	// TODO: Check IEs in request body is correct

	targetNfUri := udmURI

	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)
	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	_, _, _, _, _ = xres, sqnXorAk, ck, ik, autn

	// TODO: Check IEs in response body is correct

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
