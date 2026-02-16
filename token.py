import datetime

import jwt

SECRET = "bruvthisiscrazyyyyyyyidontgetthisshit"
token = jwt.encode(
    {
        "sub": "admin",
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=1),
    },
    SECRET,
    algorithm="HS256",
)
print(token)
