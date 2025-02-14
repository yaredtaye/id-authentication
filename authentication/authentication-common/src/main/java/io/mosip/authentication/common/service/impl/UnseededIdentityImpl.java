package io.mosip.authentication.common.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.authentication.common.service.transaction.manager.IdAuthSecurityManager;
import io.mosip.authentication.core.constant.IdAuthenticationErrorConstants;
import io.mosip.authentication.core.exception.IdAuthenticationBusinessException;
import io.mosip.authentication.core.logger.IdaLogger;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.HMACUtils2;
import lombok.NoArgsConstructor;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.TrustStrategy;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.hibernate.exception.JDBCConnectionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;
import io.mosip.authentication.common.service.repository.IdaUinHashSaltRepo;

import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UnseededIdentityImpl {
    @Autowired
    private IdaUinHashSaltRepo uinHashSaltRepo;
    private String idaClientID="mosip-ida-client";

    @Value("${mosip.ida.auth.secretKey:abc123}")
    private String idaClientSecret;

    @Value("${RETRIEVEIDENTITYFROMRID}")
    private String idRepoUrl;

    @Value("${KEYBASEDTOKENAPI}")
    private String authUrl;

    private String uinSalt="salt";

    @Autowired
    private ObjectMapper mapper = new ObjectMapper();

    private int tokenIDLength=32;

    private String partnerCodeSalt="psalt";
    private String authPartherId="mpartner-default-auth";


    private Logger mosipLogger = IdaLogger.getLogger(IdAuthSecurityManager.class);

    public UnseededIdentityImpl(String idaClientID, String idaClientSecret, String authUrl,String idRepoUrl,
                                String uinSalt,
                                int tokenIDLength, String partnerCodeSalt){
        this.idaClientSecret=idaClientSecret;
        this.idaClientID=idaClientID;
        this.authUrl=authUrl;
        this.uinSalt=uinSalt;
        this.tokenIDLength=tokenIDLength;
        this.partnerCodeSalt=partnerCodeSalt;
        this.idRepoUrl=idRepoUrl;

    }
    public UnseededIdentityImpl(){}

    public Map<String,Object> getUnseededIdentity(String id, String idType,boolean isBio, Set<String> filterAtributes,String hashedId) throws Exception {
        System.out.println("TECHNIFY: getUnseededIdentity");
        Map<String,Object> result= getDataFromIDRepo(id,idType,isBio);
        result= getNormalizedDataForID(result, filterAtributes);

        result.put("TOKEN",generateTokenID(id, authPartherId));
        result.put("ID_HASH",hashedId);

        return result;
    }

    public RestTemplate getRestTemplate()
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom()
                .loadTrustMaterial(null, acceptingTrustStrategy)
                .build();

        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);

        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(csf)
                .build();

        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory();

        requestFactory.setHttpClient(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        return restTemplate;
    }
    public HttpHeaders getAuthenticationToken() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        RestTemplate restTemplate=getRestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        JSONObject jsonObject = new JSONObject();

        try {
            jsonObject.put("id", "string");
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }

        JSONObject jsonObject1 = new JSONObject();
        try {
            jsonObject1.put("clientId", idaClientID );
            jsonObject1.put("secretKey", idaClientSecret);
            jsonObject1.put("appId", "ida");
            jsonObject.put("requesttime", "2024-06-20T09:51:46.975Z");
            jsonObject.put("version","string");
            jsonObject.put("request", jsonObject1);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }


        HttpEntity<String> entity = new HttpEntity<String>(jsonObject.toString(), headers);
        HttpEntity<String> response = restTemplate.exchange(authUrl, HttpMethod.POST, entity, String.class);

        return response.getHeaders();
    }
    private LinkedHashMap<String,Object> getDataFromIDRepo(String id, String idType, boolean isBio) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        RestTemplate restTemplate=getRestTemplate();
        String dataResult;
        LinkedHashMap<String,Object> result= null;
        String bio=isBio?"&type=bio":"";

        String url =idRepoUrl+id+"?idType="+idType+bio;

        HttpHeaders responseHeader = getAuthenticationToken();
        HttpHeaders headers1 = new HttpHeaders();

        headers1.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers1.set("Cookie", "AUTHORIZATION" + "Authorization="+responseHeader.get("Authorization").get(0));

        HttpEntity<String> entity1 = new HttpEntity<String>(headers1);
        dataResult = restTemplate.exchange(url, HttpMethod.GET, entity1, String.class).getBody();


        try {
            JSONObject jsonObject2 = new JSONObject(dataResult);
            if (jsonObject2.get("response") !=null){
                result= new LinkedHashMap<>();

                JSONObject identity =  jsonObject2.getJSONObject("response").getJSONObject("identity");
                identity.put("name", identity.getJSONArray("fullName"));
                result.put("identity", mapper.readValue(identity.toString(),Object.class));

                if(isBio){
                    result.put("Face",getPhoto(jsonObject2.getJSONObject("response").getJSONArray("documents")));
                }
            }

        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }

        return result;
    }

    private String getPhoto(JSONArray documents){
        String result="";
        try {
            if (documents != null) {
                for (int ind = 0; ind < documents.length(); ind++) {
                    if (documents.getJSONObject(ind).get("category").toString().equalsIgnoreCase("individualBiometrics")) {
                        return documents.getJSONObject(ind).get("value").toString();
                    }
                }
            }
        }catch (Exception ex){
            System.out.println(ex.getMessage());
        }
        return result;
    }
    public Map<String,Object> getNormalizedDataForID(Map<String,Object> dataToNormalize,Set<String> filterAttributes) throws Exception {
        Map<String, Object> responseMap = new LinkedHashMap<>();

        return getDemoData(dataToNormalize, filterAttributes);

    }

    public Map<String,Object> getDemoData(Map<String,Object> dataToNormalize,Set<String> filterAttributes) throws Exception {
        Map<String, Object> responseMap = new LinkedHashMap<>();
        // ObjectMapper mapper = new ObjectMapper();

        Map<String, String> demoDataMap = mapper.readValue(mapper.writeValueAsBytes(dataToNormalize.get("identity")), Map.class);

        Set<String> filterAttributesInLowercase = filterAttributes.stream().map(String::toLowerCase)
                .collect(Collectors.toSet());
        if (!filterAttributesInLowercase.isEmpty()) {
            // System.out.println(demoDataMap.get("phone"));
            Map<String, Object> demoDataMapPostFilter = demoDataMap.entrySet().stream()
                    .filter(demo -> filterAttributesInLowercase.contains(demo.getKey().toLowerCase()))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            responseMap.put("demographic",  demoDataMapPostFilter);

            if(filterAttributesInLowercase.contains("face")){
                if(dataToNormalize.containsKey("Face")){
                    Map<String,String> bio= new HashMap<>();

                    bio.put("Face", new String(Base64.getUrlDecoder().decode(dataToNormalize.get("Face").toString())));
                    responseMap.put("Face",bio);
                }
            }
        }

        return responseMap;
    }

    public String generateTokenID(String uin, String partnerCode) throws Exception {
        try {
            String uinHash = HMACUtils2.digestAsPlainText((uin + uinSalt).getBytes());
            String hash = HMACUtils2.digestAsPlainText((partnerCodeSalt + partnerCode + uinHash).getBytes());
            return new BigInteger(hash.getBytes()).toString().substring(0, tokenIDLength);
        } catch (NoSuchAlgorithmException e) {
            // TODO to be removed
            throw new Exception(e.getMessage());
        }
    }
}

