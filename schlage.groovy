/**
 *  Schlage WiFi Locks Support for Hubitat
 *  Schwark Satyavolu
 *
 */

import hubitat.helper.InterfaceUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.InvalidKeyException
import java.util.Random
import java.util.Date
import java.text.SimpleDateFormat
import java.util.TimeZone
import java.security.MessageDigest
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import groovyx.net.http.HttpResponseException
import java.time.ZoneId
import java.net.URLEncoder
import java.time.Instant


// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
def n_hex() { 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' + \
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' + \
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' + \
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' + \
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' + \
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' + \
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' + \
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF' }
// https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
def g_hex() { '2' }
def info_bits()  { 'Caldera Derived Key'.getBytes('utf-8') }
def NEW_PASSWORD_REQUIRED_CHALLENGE() { 'NEW_PASSWORD_REQUIRED' }
def PASSWORD_VERIFIER_CHALLENGE() { 'PASSWORD_VERIFIER' }
def API_KEY() { 'hnuu9jbbJr7MssFDWm5nU2Z7nG5Q5rxsaqWsE7e9' }
def BASE_URI() { 'https://api.allegion.yonomi.cloud/v1' }
def POOL_ID() { '2zhrVs9d4' }
def CLIENT_ID() { 't5836cptp2s1il0u9lki03j5' }
def CLIENT_SECRET() { '1kfmt18bgaig51in4j4v1j3jbe7ioqtjhle5o6knqc5dat0tpuvo' }
def POOL_REGION() { 'us-west-2' }
def SERVICE_NAME() { 'cognito-idp' }
def TIMEOUT() { 60 }
def LOG_MESSAGES() {
    [
        '-1': "Unknown",
        '0': "Unknown",
        '1': "Locked by keypad",
        '2': "Unlocked by keypad",
        '3': "Locked by thumbturn",
        '4': "Unlocked by thumbturn",
        '5': "Locked by Schlage button",
        '6': "Locked by mobile device",
        '7': "Unlocked by mobile device",
        '8': "Locked by time",
        '9': "Unlocked by time",
        '10': "Lock jammed",
        '11': "Keypad disabled invalid code",
        '12': "Alarm triggered",
        '14': "Access code user added",
        '15': "Access code user deleted",
        '16': "Mobile user added",
        '17': "Mobile user deleted",
        '18': "Admin privilege added",
        '19': "Admin privilege deleted",
        '20': "Firmware updated",
        '21': "Low battery indicated",
        '22': "Batteries replaced",
        '23': "Forced entry alarm silenced",
        '27': "Hall sensor comm error",
        '28': "FDR failed",
        '29': "Critical battery state",
        '30': "All access code deleted",
        '32': "Firmware update failed",
        '33': "Bluetooth firmware download failed",
        '34': "WiFi firmware download failed",
        '35': "Keypad disconnected",
        '36': "WiFi AP disconnect",
        '37': "WiFi host disconnect",
        '38': "WiFi AP connect",
        '39': "WiFi host connect",
        '40': "User DB failure",
        '48': "Passage mode activated",
        '49': "Passage mode deactivated",
        '52': "Unlocked by Apple key",
        '53': "Locked by Apple key",
        '54': "Motor jammed on fail",
        '55': "Motor jammed off fail",
        '56': "Motor jammed retries exceeded",
        '255': "History cleared"
    ]
}
def DEFAULT_UUID() { /[0-9a-f]{8}\-[f0]{4}\-[f0]{4}\-[f0]{4}\-[f0]{12}/ }


def version() {"1.0.11"}
def appVersion() { return version() }
def appName() { return "Schlage WiFi Locks" }

definition(
    name: "${appName()}",
    namespace: "schwark",
    author: "Schwark Satyavolu",
    description: "This adds support for Schlage WiFi Locks",
    category: "Convenience",
    iconUrl: "https://play-lh.googleusercontent.com/7IH82e5JiqI2_a9oWndaDyBETXtV45a-QhW_0f-ekADl6W2A3Q0u_vEWQHfQF0D-Flg=w600-h300-pc0xffffff-pd",
    iconX2Url: "https://play-lh.googleusercontent.com/7IH82e5JiqI2_a9oWndaDyBETXtV45a-QhW_0f-ekADl6W2A3Q0u_vEWQHfQF0D-Flg=w600-h300-pc0xffffff-pd",
    singleInstance: true,
    importUrl: "https://raw.githubusercontent.com/schwark/hubitat-schlage/main/schlage.groovy"
)

preferences {
    page(name: "mainPage")
    //page(name: "configPage")
}

def AWSSRP(username, password, pool_id, client_id, pool_region=null,
                client='cognito-idp', client_secret=null) {
    def result = [:]
    result.username = username
    result.password = password
    result.pool_id = pool_id
    result.client_id = client_id
    result.client_secret = client_secret
    result.client = client
    result.pool_region = pool_region
    result.big_n = hex_to_long(n_hex())
    result.g = hex_to_long(g_hex())
    result.k = hex_to_long(hex_hash('00' + n_hex() + '0' + g_hex()))
    result.small_a_value = generate_random_small_a(result)
    //result.small_a_value = hex_to_long("e1f972ab6dfd40f89b3163b2aad41608261bbc7a12e95e4a0b44dc0aefa190d0ba53cb3bea2cbb22db33fa3e2992ea759bc0c3dc60e56b0d33bb2202151d0ae8aea4c7c543c00769822a50e7f653c60649c8ad32399671988ba69ee4a1b4b259a8569efb168e96e852e249b6fe5bbea249bf0e98748d895f15f06a4002367c3e")
    result.large_a_value = calculate_a(result)
    debug("large_a_value is ${result.large_a_value}")
    return result
}

def dumpsrp(awssrp) {
    return "${awssrp.username}\n${awssrp.password}\n${awssrp.pool_id}\n${awssrp.client_id}\n${awssrp.client_secret}\n${awssrp.client}\n${awssrp.pool_region}\n${awssrp.big_n.toString(16)}\n${awssrp.g.toString(16)}\n${awssrp.k.toString(16)}\n${awssrp.small_a_value.toString(16)}\n${awssrp.large_a_value.toString(16)}"
}

def byte[] byteRange(biBytes, start, end) {
    byte[] result = new byte[end-start]
    for(i = 0; i < result.length; i++) result[i] = biBytes[start+i]
    return result
}

def concat_bytes(byte[]... arrs) {
    count = 0
    for(i = 0; i < arrs.length; i++) {
        count = count + arrs[i].length
    }
    byte[] result = new byte[count]
    current = 0
    for(i = 0; i < arrs.length; i++) {
        for(j = 0; j < arrs[i].length; j++) {
            result[current] = arrs[i][j]
            current = current + 1
        }
    }
    return result
}

def bytesFromHexString(String src) {
    /*
    byte[] biBytes = new BigInteger("10" + src.replaceAll("\\s", ""), 16).toByteArray();
    return byteRange(biBytes, 1, biBytes.length)
    */
    return src.decodeHex()
}

def hmac_sha256(secretKey, data) {
try {
    if(secretKey instanceof String) secretKey = secretKey.getBytes('utf-8')
    if(data instanceof String) data = data.getBytes('utf-8')
    Mac mac = Mac.getInstance("HmacSHA256")
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256")
    mac.init(secretKeySpec)
    return mac.doFinal(data)
} catch (InvalidKeyException e) {
    throw new RuntimeException("Invalid key exception while converting to HMac SHA256")
}
}

def hash_sha256(buf) {
    //"""AuthenticationHelper.hash"""
    return MessageDigest.getInstance("SHA-256").digest(buf).encodeHex().toString().padLeft(64, '0')
}

def hex_hash(hex_string) {
    return hash_sha256(hex_string.decodeHex())
}

def hex_to_long(hex_string) {
    return new BigInteger(hex_string, 16)
}

def long_to_hex(long_num) {
    return long_num.toString(16)
}

def get_random(nbytes) {
    def byt = new byte[nbytes]
    new Random().nextBytes(byt)
    return new BigInteger(byt)
}

def pad_hex(long_int) {
    /*
    Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
    :param {Long integer|String} long_int Number or string to pad.
    :return {String} Padded hex string.
    */
    if (long_int instanceof String) 
        hash = long_int 
    else if (long_int instanceof BigInteger) 
            hash = long_int.toString(16) 
    else hash = new BigInteger(long_int).toString(16) 

    if (hash.length() % 2 == 1) hash = '0'+hash
    else if ('89ABCDEFabcdef'.contains(hash.substring(0,1))) hash = '00' + hash
    return hash
}


def compute_hkdf(ikm, salt) {
    /*
    Standard hkdf algorithm
    :param {Buffer} ikm Input key material.
    :param {Buffer} salt Salt value.
    :return {Buffer} Strong key material.
    @private
    */
    def prk = hmac_sha256(salt, ikm)
    def info_bits_update = concat_bytes(info_bits(), Character.toString((char)1).getBytes('utf-8'))
    def hmac_hash = hmac_sha256(prk, info_bits_update)
    return byteRange(hmac_hash, 0, 16)
}


def calculate_u(big_a, big_b) {
    /*
    Calculate the client's value U which is the hash of A and B
    :param {Long integer} big_a Large A value.
    :param {Long integer} big_b Server B value.
    :return {Long integer} Computed U value.
    */
    debug("hex_big_a : "+pad_hex(big_a))
    debug("hex_big_b : "+pad_hex(big_b))
    def u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
    debug("hex_u : "+u_hex_hash)
    return hex_to_long(u_hex_hash)
}

def generate_random_small_a(awssrp) {
    /*
    helper function to generate a random big integer
    :return {Long integer} a random value.
    */
    def random_long_int = get_random(128)
    return random_long_int % awssrp.big_n
}

def calculate_a(awssrp) {
    /*
    Calculate the client's public value A = g^a%N
    with the generated random number a
    :param {Long integer} a Randomly generated small A.
    :return {Long integer} Computed large A.
    */
    debug("hex_small_a : "+pad_hex(awssrp.small_a_value))
    debug("hex_big_n : "+pad_hex(awssrp.big_n))
    def big_a = awssrp.g.modPow(awssrp.small_a_value, awssrp.big_n)
    debug("hex_big_a : "+pad_hex(big_a))
    // safety check
    if (big_a.mod(awssrp.big_n) == 0) {
        throw ValueError('Safety check for A failed')
    }
    return big_a
}

def get_password_authentication_key(awssrp, username, password, server_b_value, salt) {
    /*
    Calculates the final hkdf based on computed S value, and computed U value and the key
    :param {String} username Username.
    :param {String} password Password.
    :param {Long integer} server_b_value Server B value.
    :param {Long integer} salt Generated salt.
    :return {Buffer} Computed HKDF value.
    */
    def u_value = calculate_u(awssrp.large_a_value, server_b_value)
    if (u_value == 0) throw ValueError('U cannot be zero.')
    def username_password = "${awssrp.pool_id}${username}:${password}"
    debug(username_password)
    def username_password_hash = hash_sha256(username_password.getBytes('utf-8'))
    debug("user_pass_hash : "+username_password_hash)
    def x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
    def g_mod_pow_xn = awssrp.g.modPow(x_value, awssrp.big_n)
    def int_value2 = server_b_value - awssrp.k * g_mod_pow_xn
    def s_value = int_value2.modPow(awssrp.small_a_value + u_value * x_value, awssrp.big_n)
    debug("small_a_value : "+long_to_hex(awssrp.small_a_value))
    debug("s_value : "+long_to_hex(s_value))
    debug("u_value : "+long_to_hex(u_value))
    def hkdf = compute_hkdf(bytesFromHexString(pad_hex(s_value)),
                        bytesFromHexString(pad_hex(long_to_hex(u_value))))
    return hkdf
}

def get_auth_params(awssrp) {
    def auth_params = ['USERNAME': awssrp.username,
                    'SRP_A': long_to_hex(awssrp.large_a_value)]
    add_secret_hash(awssrp, auth_params)
    return auth_params
}

def get_secret_hash(awssrp) {
    def message = (awssrp.username + awssrp.client_id).getBytes('utf-8')
    def hmac_obj = hmac_sha256(awssrp.client_secret.getBytes('utf-8'), message)
    return hmac_obj.encodeBase64().toString()
}

def get_utc_timestamp() {
    final Date date = new Date()
    final String AWS_FORMAT = "EEE MMM d HH:mm:ss z YYYY";
    final SimpleDateFormat sdf = new SimpleDateFormat(AWS_FORMAT);
    final TimeZone utc = TimeZone.getTimeZone("UTC");
    sdf.setTimeZone(utc);
    return sdf.format(date)
}

def add_secret_hash(awssrp, auth_params) {
    if (awssrp.client_secret) {
        auth_params["SECRET_HASH"] = get_secret_hash(awssrp)
    }   
}

def process_challenge(challenge_parameters) {
    def awssrp = state.awssrp
    def user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
    def salt_hex = challenge_parameters['SALT']
    def srp_b_hex = challenge_parameters['SRP_B']
    def secret_block_b64 = challenge_parameters['SECRET_BLOCK']
    def timestamp = get_utc_timestamp()
    def hkdf = get_password_authentication_key(awssrp, user_id_for_srp,
                                                awssrp.password, hex_to_long(srp_b_hex), salt_hex)
    debug("hkdf is ${hkdf.encodeHex()}")
    def secret_block_bytes = secret_block_b64.decodeBase64()
    def msg = concat_bytes(awssrp.pool_id.getBytes('utf-8'), user_id_for_srp.getBytes('utf-8'),
        secret_block_bytes, timestamp.getBytes('utf-8'))
    debug("msg is ${msg.encodeHex()}")
    def hmac_obj = hmac_sha256(hkdf, msg)
    def signature_string = hmac_obj.encodeBase64().toString()
    debug("signature is ${signature_string}")
    def response = ['TIMESTAMP': timestamp,
                'USERNAME': user_id_for_srp,
                'PASSWORD_CLAIM_SECRET_BLOCK': secret_block_b64,
                'PASSWORD_CLAIM_SIGNATURE': signature_string]
    add_secret_hash(awssrp, response)
    return response
}

def aws_cognito(awssrp, method, data=null, closure) {
    def contentType = "application/x-amz-json-1.1"
    def headers =  [
        'X-Amz-Target': "AWSCognitoIdentityProviderService.${method}",
        'Content-Type': contentType,
        'User-Agent': 'Botocore/0.103.0 Python/2.7.6 Linux/3.13.0-49-generic'
    ]
    def uri = "https://${awssrp.client}.${awssrp.pool_region}.amazonaws.com/"
    if('RespondToAuthChallenge' == method) {
       // uri = "https://webhook.site/f4b6fbca-e579-443b-bc8a-c307a07084ac"
    }

    debug("aws cognito uri: ${uri} --- data: ${data}")
    if(data) {
        try {
            httpPost([uri: uri, headers: headers, body: JsonOutput.toJson(data), textParser: true], closure)
        } catch (HttpResponseException e) {
            def response = e.response
            debug(response.data.text)
        }
    } else {
        httpGet([uri: uri, headers: headers, contentType: contentType], closure)
    }
}

def schedule_renewal() {
    debug("updating last updated on token to ${now()}")
    state.access_token_updated = now()
    runIn(state.tokens['ExpiresIn']-300, renew_access_token)
}

def ensure_access_token() {
    debug("token_updated : ${state.access_token_updated}")
    debug("now : ${now()}")
    if(!state.tokens || !state.access_token_updated || now() - state.access_token_updated > state.tokens['ExpiresIn']*1000) {
        authenticate_user()
    }
}

def renew_access_token() {
    /*
    Sets a new access token on the User using the cached refresh token.
    */
    def awssrp = state.awssrp
    def refresh_token = state.tokens['RefreshToken']
    def auth_params = ["REFRESH_TOKEN": refresh_token]
    add_secret_hash(awssrp, auth_params)
    def data = [
        ClientId: awssrp.client_id,
        AuthFlow: "REFRESH_TOKEN_AUTH",
        AuthParameters: auth_params
    ]
    aws_cognito(awssrp, 'InitiateAuth', data, { 
        def body = it.data.text
        debug(body)
        jslurp = new JsonSlurper()
        def tokens = jslurp.parseText(body)
        state.tokens = tokens['AuthenticationResult']
        if(!state.tokens['RefreshToken']) state.tokens['RefreshToken'] = refresh_token
        schedule_renewal()
    })
}

def schlage_api(path, data=null, method=null, closure) {
    def access_token = state.tokens['AccessToken']
    def contentType = 'application/json'
    def headers = [
        'X-Api-Key': API_KEY(),
        'Authorization': "Bearer ${access_token}"
    ]
    def uri = "${BASE_URI()}/${path}"
    method = method ?: (data ? 'POST' : 'GET')
    if(data && 'GET' == method) {
        params = data.collect {k,v -> "${URLEncoder.encode(k.toString())}=${URLEncoder.encode(v.toString())}"}.join('&')
        uri = "${uri}?${params}"
        data = null
    }
    debug("uri: ${uri}, data: ${data}, method: ${method}")
    "http${method.toLowerCase().capitalize()}"([uri: uri, headers: headers, body: data, contentType: contentType, timeout: TIMEOUT()], closure)
}

def send_lock_command(deviceId, command, data, closure) {
    def body = [
        data: data,
        name: command
    ]
    def path = "devices/${deviceId}/commands"
    return schlage_api(path, body, null, closure)
}

def change_lock_state(deviceId, locked) {
    def lock = state.locks[deviceId]
    def wifi = is_wifi(deviceId)
    def use_put = (wifi && lockMethod == 'auto') || lockMethod == 'put'
    def control_device = lock.bridge ?: deviceId
    def data = use_put ? [
        attributes: [
            lockState: locked
        ]
    ] : [
        CAT: lock.cat,
        deviceId: deviceId,
        state: locked,
        userId: lock.user        
    ]
    return use_put ? schlage_api("devices/${deviceId}", data, 'PUT', {}) : send_lock_command(control_device, "changelockstate", data, {})
}

def get_logs(deviceId) {
    def path = "devices/${deviceId}/logs"
    state.last_log = state.last_log ?: Long(0L)
    debug(state.users)
    schlage_api(path, [sort: 'desc', limit: 10], 'GET') {
        json = it.data
        debug(json)
        Long skipTime = 0
        json.each {
            Long log_time = it.message.secondsSinceEpoch
            if(it.logId == state.last_log) skipTime = log_time
            if(log_time <= skipTime) return
            log_time = log_time*1000
            def dt = new Date(log_time)
            def user = get_user_for_id(deviceId, it.message.accessorUuid)
            def code = get_code_for_id(deviceId, it.message.keypadUuid)
            def message = LOG_MESSAGES()["${it.message.eventCode}"]
            debug("${log_time} : ${message} : ${it.message.accessorUuid} : ${it.message.keypadUuid}")
            message = "${dt} : ${message}${user ? ' by '+user : ''}${code ? ' with '+code : ''}"
            log.info("[Schlage Locks] INFO: ${message}")
        }
        state.last_log = json[0].logId
    }
}

def delete_code(deviceId, codeId) {
    schlage_api("devices/${deviceId}/storage/accesscode/${codeId}", null, 'DELETE') {
    }
}

def lock(deviceId) {
    return change_lock_state(deviceId, 1)
}

def unlock(deviceId) {
    return change_lock_state(deviceId, 0)
}

def update_access_codes(deviceId=null) {
    state.codes = state.codes ?: [:]
    devices = deviceId ? [deviceId] : state.locks.keySet()
    devices.each {
        deviceId = it
        schlage_api("devices/${deviceId}/storage/accesscode", null, null) {
            json = it.data
            def counter = json.size()
            json.each {
                code = [
                    id: it.accesscodeId,
                    name: it.friendlyName,
                    code: it.accessCode,
                    notify: it.notification,
                    disabled: it.disabled,
                    device: deviceId,
                    position: counter
                ]
                counter = counter - 1
                state.locks[deviceId].codes[it.accesscodeId] = code
            }
        }
    }
    debug(state.locks)
}

def is_wifi(deviceId) {
    def lock = state.locks[deviceId]
    if(lock.model.startsWith('be489') || lock.model.startsWith('be499') || lock.model.startsWith('fe789')) return true
    return false
}

def update_locks() {
    state.locks = state.locks ?: [:]
    state.users = state.users ?: [:]
    schlage_api("devices", null, null) {
        def body = it.data
        debug(it.data)
        json = it.data
        json.each {
            def deviceId = it.deviceId
            lock = [
                name: it.name,
                id: deviceId,
                state: it.attributes.lockState,
                cat: it.CAT,
                user: it.users[0].identityId,
                model: it.modelName,
                bridge: it.relatedDevices ? it.relatedDevices[0].deviceId : null,
                codes: [:], 
                users: [:]
            ]
            state.locks[deviceId] = lock
            createChildDevice(it.name, deviceId)
            getChildDevice(deviceId).sendEvent(name: 'lock', value: (it.attributes.lockState ? 'locked' : 'unlocked'))
            def counter = 0
            it.users.each {
                user = [
                    name: it.friendlyName,
                    id: it.identityId,
                    email: it.email,
                    role: it.role,
                    position: counter
                ]
                counter = counter + 1
                state.locks[deviceId].users[it.identityId] = user
            }
            get_logs(deviceId)
        }
    }
    debug(state.locks)
}

def get_code_for_id(deviceId, id) {
    if(!id || id ==~ DEFAULT_UUID()) return null
    name = state.locks[deviceId].codes.find { it.value.id == id }?.name
    return name ? name : id
}

def get_user_for_id(deviceId, id) {
    if(!id || id ==~ DEFAULT_UUID()) return null
    name = state.locks[deviceId].users.find { it.value.id == id }?.name
    return name ? name : id
}

def authenticate_user() {
    def awssrp = state.awssrp
    def auth_params = get_auth_params(awssrp)
    def data = [ 
        AuthFlow: 'USER_SRP_AUTH',
        AuthParameters: auth_params,
        ClientId: awssrp.client_id
    ]
    debug(data)
    aws_cognito(awssrp, 'InitiateAuth', data, { 
        def body = it.data.text
        debug(body)
        jslurp = new JsonSlurper()
        def response = jslurp.parseText(body)
        it.headers.each { header ->
         debug "${header.name} : ${header.value}"
        }
        if (response['ChallengeName'] == PASSWORD_VERIFIER_CHALLENGE()) {
            challenge_response = process_challenge(response['ChallengeParameters'])
            data = [
                ClientId: awssrp.client_id,
                ChallengeName: PASSWORD_VERIFIER_CHALLENGE(),
                ChallengeResponses: challenge_response
            ]
            aws_cognito(awssrp, 'RespondToAuthChallenge', data, {  
                body = it.data.text
                debug(body)
                def tokens = jslurp.parseText(body)
                if (tokens.get('ChallengeName') == NEW_PASSWORD_REQUIRED_CHALLENGE()) throw Exception('Change password before authenticating')
                state.tokens = tokens['AuthenticationResult']
                schedule_renewal()
            })
        }
        else
            throw NotImplementedError("The ${response['ChallengeName']} challenge is not supported")
    })        
}

def date_to_local(date) {
    return date.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime()
}

def timestamp_to_date(timestamp) {
    return Date.parse("yyyy-MM-dd'T'HH:mm:ss.SSSZ", timestamp.replaceAll('Z$', '+0000'))
}

def getFormat(type, myText=""){
    if(type == "section") return "<div style='color:#78bf35;font-weight: bold'>${myText}</div>"
    if(type == "hlight") return "<div style='color:#78bf35'>${myText}</div>"
    if(type == "header") return "<div style='color:#ffffff;background-color:#392F2E;text-align:center'>${myText}</div>"
    if(type == "redhead") return "<div style='color:#ffffff;background-color:red;text-align:center'>${myText}</div>"
    if(type == "line") return "\n<hr style='background-color:#78bf35; height: 2px; border: 0;'></hr>"
    if(type == "centerBold") return "<div style='font-weight:bold;text-align:center'>${myText}</div>"    
    
}

def mainPage(){
    dynamicPage(name:"mainPage",install:true, uninstall:true){
        section {
            input "debugMode", "bool", title: "Enable debugging", defaultValue: true
            input "allowUnlock", "bool", title: "Allow Unlocking", defaultValue: true
            input "lockMethod", "enum", title: "Lock/Unlock Method", options: ['auto', 'put', 'post'], defaultValue: 'auto'
        }
        section(getFormat("header", "Login Information")) {
            input "username", "text", title: "Username", required: true
            input "password", "text", title: "Password", required: true
        }
    }
}

def configPage(){
    refresh()
    dynamicPage(name: "configPage", title: "Configure/Edit Presets:") {
        section(""){input("numPresets", "number", title: getFormat("section", "How many presets?:"), submitOnChange: true, range: "1..25")}
            if(numPresets){
                for(i in 1..numPresets){
                    section(getFormat("header", "Preset ${i}")){
                        input("speaker${i}", "enum", title: getFormat("section", "Speaker:"), options: state.speakers)
                        input("preset${i}", "enum", title: getFormat("section", "Preset:"), options: state.presets, submitOnChange: true)
                    }
                }
            }
    }
}

def installed() {
    initialize()
}

def updated() {
    initialize()
    def force = false
    if(!state.last_username || state.last_username != username || !state.last_password || state.last_password != password) {
        state.last_username = username
        state.last_password = password
        force = true
    }
    refresh(force)
    runEvery1Minute('refresh')
}

def initialize() {
    unschedule()
}

def uninstalled() {
    def children = getAllChildDevices()
    log.info("uninstalled: children = ${children}")
    children.each {
        deleteChildDevice(it.deviceNetworkId)
    }
}

def componentUnlock(cd) {
    if(allowUnlock) {
        unlock(cd.deviceNetworkId)
        cd.sendEvent(name:'lock', value: 'unlocked')
    }
}

def componentLock(cd) {
    lock(cd.deviceNetworkId)
    cd.sendEvent(name:'lock', value: 'locked')
}

def componentGetCodes(cd) {
    update_access_codes(cd.deviceNetworkId)
}

def componentDeleteCode(cd, position) {
    def deviceId = cd.deviceNetworkId
    def code = state.locks[deviceId].codes.find { it.position == position }
    delete_code(deviceId, code.id)
}

def componentRefresh(cd) {
    refresh()
}

def refresh(force=false) {
    debug("refreshing Schlage Locks...")
    state.awssrp = AWSSRP(username, password, POOL_ID(), CLIENT_ID(), POOL_REGION(), SERVICE_NAME(), CLIENT_SECRET())
    debug(dumpsrp(state.awssrp))
    ensure_access_token()
    debug(state.tokens)
    update_locks()
    update_access_codes()
}

private createChildDevice(label, id) {
    def deviceId = id
    def createdDevice = getChildDevice(deviceId)
    def name = "Schlage Lock"

    if(!label.contains(' Lock')) label = "${label} Lock"
    if(!createdDevice) {
        try {
            def component = 'Generic Component Lock'
            // create the child device
            addChildDevice("hubitat", component, deviceId, [label : "${label}", isComponent: false, name: "${name}"])
            createdDevice = getChildDevice(deviceId)
            def created = createdDevice ? "created" : "failed creation"
            log.info("[Schlage Lock] id: ${deviceId} label: ${label} ${created}")
        } catch (e) {
            logError("Failed to add child device with error: ${e}", "createChildDevice()")
        }
    } else {
        debug("Child device id: ${deviceId} already exists", "createChildDevice()")
        if(label && label != createdDevice.getLabel()) {
            createdDevice.setLabel(label)
            createdDevice.sendEvent(name:'label', value: label, isStateChange: true)
        }
        if(name && name != createdDevice.getName()) {
            createdDevice.setName(name)
            createdDevice.sendEvent(name:'name', value: name, isStateChange: true)
        }
    }
    return createdDevice
}

private debug(logMessage, fromMethod="") {
    if (debugMode) {
        def fMethod = ""

        if (fromMethod) {
            fMethod = ".${fromMethod}"
        }

        log.debug("[Schlage Locks] DEBUG: ${fMethod}: ${logMessage}")
    }
}

private logError(fromMethod, e) {
    log.error("[Schlage Locks] ERROR: (${fromMethod}): ${e}")
}
