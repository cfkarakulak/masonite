import inspect
import os

from ...utils.filesystem import get_module_dir


def is_property(obj):
    return not inspect.ismethod(obj)


def is_local(obj_name, obj):
    return (
        not obj_name.startswith("__")
        and not obj_name.endswith("__")
        and type(obj).__name__ != "builtin_function_or_method"
    )


def serialize_property(obj):
    if isinstance(obj, list):
        return [serialize_property(subobj) for subobj in obj]
    elif isinstance(obj, dict):
        return {key: serialize_property(val) for key, val in obj.items()}
    elif hasattr(obj, "serialize"):
        return obj.serialize()
    else:
        return str(obj)


class DumpExceptionHandler:
    def __init__(self, application):
        self.application = application

        self.assets_path = os.path.join(
            get_module_dir(__file__), "../../templates/assets"
        )
        self.styles = []
        self.scripts = []

    def add_style(self, file):
        with open(os.path.join(self.assets_path, file), "r") as f:
            self.styles.append(f.read())

    def add_script(self, file):
        with open(os.path.join(self.assets_path, file), "r") as f:
            self.scripts.append(f.read())

    def get_scripts(self):
        return "".join(f"<script>{script}</script>\n" for script in self.scripts)

    def get_styles(self):
        return "".join(f"<style>{style}</style>\n" for style in self.styles)

    def handle(self, exception):
        dumps = []
        # for dump in self.application.make("dumper").get_dumps():
        # for obj_name, obj in dump.objects.items():
        # all_members = inspect.getmembers(obj, predicate=inspect.ismethod)
        # all_properties = inspect.getmembers(obj, predicate=is_property)
        # members = {
        #     name: str(member)
        #     for name, member in all_members
        #     if is_local(name, member)
        # }
        # properties = {
        #     name: serialize_property(prop)
        #     for name, prop in all_properties
        #     if is_local(name, prop)
        # }
        # dumps.append(
        #     {
        #         "name": obj_name,
        #         "obj": str(obj),
        #         "members": members,
        #         "properties": properties,
        #     }
        # )
        dumps = self.application.make("dumper").get_serialized_dumps()
        self.add_style("tailwind.css")
        self.add_style("github-dark.min.css")
        self.add_script("highlight.min.js")

        return self.application.make("response").view(
            self.application.make("view").render(
                "/masonite/templates/dump",
                {
                    "styles": self.get_styles(),
                    "scripts": self.get_scripts(),
                    "dumps": dumps,
                },
            )
        )
