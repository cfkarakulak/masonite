class PrivateChannel:
    def __init__(self, name):
        if not name.startswith("private-"):
            name = f"private-{name}"

        self.name = name

    def authorized(self, application):
        return bool(application.make("request").user())
