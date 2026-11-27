"""English catalog: keys are `<area>.<name>`; each module holds one area."""
from . import common, failover, fleet, instances, people, python

STRINGS = {**common.S, **failover.S, **fleet.S, **instances.S, **people.S, **python.S}
