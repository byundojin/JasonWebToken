import base64
import hashlib
import datetime
import uuid

def base_encode(msg:str) -> str:
    return base64.b64encode(msg.encode()).decode()
def base_decode(msg:str) -> str:
    return base64.b64decode(msg.encode()).decode()
def hash_encode(msg:str) -> str:
    return hashlib.sha256(msg.encode()).hexdigest()
def time_now() -> datetime.datetime:
    return datetime.datetime.now()
def str_to_time(time:str) -> datetime.datetime:
    return datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
def time_to_str(time:datetime.datetime) -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S')
def make_signature(encode_header:str, encode_payload:str) -> str:
    return hash_encode(f"{encode_header}.{encode_payload}.{Token.secret_key}")


class Token():
    secret_key = "dgfgdg"
    access_token_time = 6000
    refresh_token_time = 360000

    def __new__(cls):
        if hasattr(cls, "_instance"):
            cls.instance = super().__new__(cls)
        return cls.instance

    def create(**kwarg) -> str:
        header = {
            "ver":"1.0.0",
            "typ":"jwt",
            "alg":"sha256"
        }
        payload = {
            "iat": time_to_str(time_now())
        }
        payload.update(kwarg)
        encode_header = base_encode(str(header))
        encode_payload = base_encode(str(payload))
        signature = make_signature(encode_header, encode_payload)
        return f"{encode_header}.{encode_payload}.{signature}"
    
    def is_vaild(token:str, time_ckeck=False):
        encode_header, encode_payload, signature = token.split(".")
        if make_signature(encode_header, encode_payload) != signature:
            raise "토큰 변조됨"
        payload = base_decode(encode_payload)
        payload:dict = eval(payload)
        if time_ckeck:
            if not "iat" in payload:
                raise "claim 없음 -> iat"
            if not "typ" in payload:
                raise "claim 없음 -> typ"
            if payload["typ"] == "access_token":
                token_time = Token.access_token_time
            elif payload["typ"] == "refresh_token":
                token_time = Token.refresh_token_time
            else:
                raise "typ 오류"
            time = time_now()
            iat_time = str_to_time(payload["iat"])
            if (time - iat_time).seconds > token_time:
                raise "token time out"
        return payload
        
    
    def set_access_token_time(second:int):
        Token.access_token_time = second
    def set_refresh_token_time(second:int):
        Token.refresh_token_time = second
    def set_secret_key(key:str):
        Token.secret_key = key
        
token = (Token.create(typ="access_token"))
print(token)
print(Token.is_vaild(token, time_ckeck=True))
