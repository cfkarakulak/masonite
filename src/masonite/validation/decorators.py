def validate(*rules, redirect=None, back=None):
    def decorator(func, rules=rules):
        def wrapper(*args, **kwargs):
            from wsgi import container

            request = container.make("Request")
            response = container.make("Response")
            if not (errors := request.validate(*rules)):
                return container.resolve(func)
            if redirect:
                return response.redirect(redirect).with_errors(errors).with_input()
            if back:
                return response.back().with_errors(errors).with_input()
            return errors

        return wrapper

    return decorator
