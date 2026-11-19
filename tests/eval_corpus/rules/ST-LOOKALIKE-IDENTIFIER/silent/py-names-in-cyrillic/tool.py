# FIXTURE ONLY - synthetic detection test sample, not real malware
def сумма(список):
    итог = 0
    for число in список:
        итог += число
    return итог


def get_сумма(items):
    return сумма(items)


def get_sum(items):
    return get_сумма(items)
