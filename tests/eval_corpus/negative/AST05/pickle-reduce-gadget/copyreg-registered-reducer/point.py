# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: custom pickling registered with copyreg, and an attribute looked up by name on
# an object. The reducer returns the class and its constructor arguments, as pickling is meant to.
import copyreg


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def describe(self, field):
        return getattr(self, field)


def reduce_point(p):
    cls = type(p)
    return (cls, (p.x, p.y))


copyreg.pickle(Point, reduce_point)
