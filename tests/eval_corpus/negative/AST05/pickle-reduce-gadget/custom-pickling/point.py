# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: ordinary custom pickling. __reduce__ returns the class (or a factory) and
# its constructor arguments -- the documented, honest use -- and must stay clean.
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __reduce__(self):
        return (self.__class__, (self.x, self.y))


def _make_vector():
    return Vector()


class Vector:
    def __reduce_ex__(self, protocol):
        return (_make_vector, ())
