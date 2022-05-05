from ..controllers.ViewController import ViewController
from .HTTPRoute import HTTPRoute
from ..utils.collections import flatten
from ..utils.str import modularize
from ..controllers import RedirectController


class Route:

    routes = []
    compilers = {
        "int": r"(\d+)",
        "integer": r"(\d+)",
        "string": r"([a-zA-Z]+)",
        "default": r"([\w.-]+)",
        "signed": r"([\w\-=]+)",
    }
    controllers_locations = []

    def __init__(self):
        pass

    @classmethod
    def get(cls, url, controller, module_location=None, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["get"],
            compilers=cls.compilers,
            controllers_locations=module_location or cls.controllers_locations,
            **options
        )

    @classmethod
    def post(cls, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["post"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def put(cls, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["put"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def patch(cls, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["patch"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def delete(cls, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["delete"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def options(cls, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=["options"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def default(cls, url, controller, **options):
        return cls

    @classmethod
    def redirect(cls, url, new_url, **options):
        return HTTPRoute(
            url,
            RedirectController.redirect,
            request_method=["get"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            controller_bindings=[new_url, options.get("status", 302)],
            **options
        )

    @classmethod
    def view(cls, url, template, data=None, **options):
        if not data:
            data = {}

        return HTTPRoute(
            url,
            ViewController.show,
            request_method=options.get("method", ["get"]),
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            controller_bindings=[template, data],
            **options
        )

    @classmethod
    def permanent_redirect(cls, url, new_url, **options):
        return HTTPRoute(
            url,
            RedirectController.redirect,
            request_method=["get"],
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            controller_bindings=[new_url, 301],
            **options
        )

    @classmethod
    def match(cls, request_methods, url, controller, **options):
        return HTTPRoute(
            url,
            controller,
            request_method=request_methods,
            compilers=cls.compilers,
            controllers_locations=cls.controllers_locations,
            **options
        )

    @classmethod
    def group(cls, *routes, **options):
        inner = []
        for route in flatten(routes):
            if options.get("prefix"):
                if route.url == "" or route.url == "/":
                    route.url = options.get("prefix")
                else:
                    route.url = options.get("prefix") + route.url

                route.compile_route_to_regex()

            if options.get("name"):
                route._name = options.get("name") + route._name

            if options.get("domain"):
                route.domain(options.get("domain"))

            if options.get("middleware"):
                middleware = route.list_middleware
                middleware = options.get("middleware", []) + middleware

                route.set_middleware(middleware)

            inner.append(route)
        cls.routes = inner
        return inner

    @classmethod
    def resource(cls, base_url, controller):
        return [
            cls.get(f"/{base_url}", f"{controller}@index").name(
                f"{base_url}.index"
            ),
            cls.get(f"/{base_url}/create", f"{controller}@create").name(
                f"{base_url}.create"
            ),
            cls.post(f"/{base_url}", f"{controller}@store").name(
                f"{base_url}.store"
            ),
            cls.get(f"/{base_url}/@id", f"{controller}@show").name(
                f"{base_url}.show"
            ),
            cls.get(f"/{base_url}/@id/edit", f"{controller}@edit").name(
                f"{base_url}.edit"
            ),
            cls.match(
                ["put", "patch"], f"/{base_url}/@id", f"{controller}@update"
            ).name(f"{base_url}.update"),
            cls.delete(f"/{base_url}/@id", f"{controller}@destroy").name(
                f"{base_url}.destroy"
            ),
        ]

    @classmethod
    def api(cls, base_url, controller):
        return [
            cls.get(f"/{base_url}", f"{controller}@index").name(
                f"{base_url}.index"
            ),
            cls.post(f"/{base_url}", f"{controller}@store").name(
                f"{base_url}.store"
            ),
            cls.get(f"/{base_url}/@id", f"{controller}@show").name(
                f"{base_url}.show"
            ),
            cls.match(
                ["put", "patch"], f"/{base_url}/@id", f"{controller}@update"
            ).name(f"{base_url}.update"),
            cls.delete(f"/{base_url}/@id", f"{controller}@destroy").name(
                f"{base_url}.destroy"
            ),
        ]

    @classmethod
    def compile(cls, key, to=""):
        cls.compilers.update({key: to})
        return cls

    @classmethod
    def set_controller_locations(cls, *controllers_locations):
        cls.controllers_locations = list(map(modularize, controllers_locations))
        return cls

    @classmethod
    def add_controller_locations(cls, *controllers_locations):
        cls.controllers_locations.extend(list(map(modularize, controllers_locations)))
        return cls
