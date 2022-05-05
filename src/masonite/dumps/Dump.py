import time
import inspect
from pprint import pformat


def color(string):
    return f"\033[93m{string}\033[0m"


def is_property(obj):
    return not inspect.ismethod(obj)


def is_local(obj_name, obj):
    return (
        not obj_name.startswith("__")
        and not obj_name.endswith("__")
        and type(obj).__name__ != "builtin_function_or_method"
    )


def is_private(obj_name):
    return obj_name.startswith("_")


def serialize_property(obj):
    if isinstance(obj, list):
        return [serialize_property(subobj) for subobj in obj]
    elif isinstance(obj, dict):
        return {key: serialize_property(val) for key, val in obj.items()}
    elif hasattr(obj, "serialize"):
        return obj.serialize()
    else:
        return str(obj)


class Dump:
    def __init__(self, objects, method, filename, line):
        self.objects = objects
        self.method = method
        self.filename = filename
        self.line = line
        self.timestamp = time.time()

    def serialize(self):
        objects = {}
        for name, obj in self.objects.items():
            # serialize all obj properties
            all_properties = inspect.getmembers(obj, predicate=is_property)
            local_properties = {"private": {}, "public": {}}
            for prop_name, prop in all_properties:
                if is_local(prop_name, prop):
                    entry = {prop_name: serialize_property(prop)}
                    if is_private(prop_name):
                        local_properties["private"].update(entry)
                    else:
                        local_properties["public"].update(entry)

            objects[name] = {"value": str(obj), "properties": local_properties}

        return {
            "objects": objects,
            "method": self.method,
            "filename": self.filename,
            "line": self.line,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return self._format()

    def __str__(self):
        return self._format()

    def _format(self):
        """Format the dump as string to be printed in console."""
        output = f"\n{color('>>> DUMP')} from {self.filename}: {color(f'L{self.line}')} in {color(f'{self.method}()')}"

        for name, obj in self.objects.items():
            output += f"\n\n{color(f'  - {name}:')}\n"
            output += f"  {pformat(obj, width=110, indent=4)}"

        output += color("\n\n<<< END")
        return output
