# FIXTURE ONLY - synthetic detection test sample, not real malware
# Проверка tokenа пользователя (chеck_token)
def check_token(t):
    message = 'SMSка отправлена, chеck_token'
    return t == 'expected', message
