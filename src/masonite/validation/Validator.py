import inspect
import re
import os
import mimetypes

from .RuleEnclosure import RuleEnclosure
from .MessageBag import MessageBag
from ..utils.structures import data_get
from ..configuration import config
from ..facades import Loader


class BaseValidation:
    def __init__(self, validations, messages={}, raises={}):
        self.errors = {}
        self.messages = messages
        if isinstance(validations, str):
            self.validations = [validations]
        else:
            self.validations = validations
        self.negated = False
        self.raises = raises

    def passes(self, attribute, key, dictionary):
        return True

    def error(self, key, message):
        if key in self.messages:
            if key in self.errors:
                self.errors[key].append(self.messages[key])
                return
            self.errors.update({key: [self.messages[key]]})
            return

        if not isinstance(message, list):
            self.errors.update({key: [message]})
        else:
            self.errors.update({key: message})

    def find(self, key, dictionary, default=""):
        return data_get(dictionary, key, default)

    def message(self, key):
        return ""

    def negate(self):
        self.negated = True
        return self

    def raise_exception(self, key):
        if self.raises is not True and key in self.raises:
            error = self.raises.get(key)
            raise error(self.errors[next(iter(self.errors))][0])

        raise ValueError(self.errors[next(iter(self.errors))][0])

    def handle(self, dictionary):
        boolean = True

        for key in self.validations:
            if self.negated:

                if self.passes(self.find(key, dictionary), key, dictionary):
                    boolean = False
                    if hasattr(self, "negated_message"):
                        self.error(key, self.negated_message(key))
                    else:
                        self.error(key, self.message(key))

                continue
            attribute = self.find(key, dictionary)
            if not self.passes(attribute, key, dictionary):
                boolean = False
                self.error(key, self.message(key))

            if self.errors and self.raises:
                return self.raise_exception(key)

        return boolean

    def reset(self):
        self.errors = {}


class required(BaseValidation):
    def passes(self, attribute, key, dictionary):
        """The passing criteria for this rule.

        The key must exist in the dictionary and return a True boolean value.
        The key can use * notation.

        Arguments:
            attribute {mixed} -- The value found within the dictionary
            key {string} -- The key in the dictionary being searched for.
            dictionary {dict} -- The dictionary being searched

        Returns:
            bool
        """
        return self.find(key, dictionary) and attribute

    def message(self, key):
        """A message to show when this rule fails

        Arguments:
            key {string} -- The key used to search the dictionary

        Returns:
            string
        """
        return f"The {key} field is required."

    def negated_message(self, key):
        """A message to show when this rule is negated using a negation rule like 'isnt()'

        For example if you have a message that says 'this is required' you may have a negated statement
        that says 'this is not required'.

        Arguments:
            key {string} -- The key used to search the dictionary

        Returns:
            string
        """
        return f"The {key} field is not required."


class timezone(BaseValidation):
    def passes(self, attribute, key, dictionary):
        import pytz

        return attribute in pytz.all_timezones

    def message(self, attribute):
        return f"The {attribute} must be a valid timezone."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a valid timezone."


class one_of(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return any(validation in dictionary for validation in self.validations)

    def message(self, attribute):
        if len(self.validations) > 2:
            text = ", ".join(self.validations)
        else:
            text = " or ".join(self.validations)

        return f"The {text} is required."

    def negated_message(self, attribute):
        if len(self.validations) > 2:
            text = ", ".join(self.validations)
        else:
            text = " or ".join(self.validations)

        return f"The {text} is not required."


class accepted(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return (
            attribute is True
            or attribute == "on"
            or attribute == "yes"
            or attribute == "1"
            or attribute == 1
        )

    def message(self, attribute):
        return f"The {attribute} must be accepted."

    def negated_message(self, attribute):
        return f"The {attribute} must not be accepted."


class ip(BaseValidation):
    def passes(self, attribute, key, dictionary):
        import socket

        try:
            socket.inet_aton(attribute)
            return True
        except socket.error:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a valid ipv4 address."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a valid ipv4 address."


class date(BaseValidation):
    def passes(self, attribute, key, dictionary):
        import pendulum

        try:
            return pendulum.parse(attribute)
        except pendulum.parsing.exceptions.ParserError:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a valid date."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a valid date."


class before_today(BaseValidation):
    def __init__(self, validations, tz="UTC", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.tz = tz

    def passes(self, attribute, key, dictionary):
        import pendulum

        try:
            return pendulum.parse(attribute, tz=self.tz) <= pendulum.yesterday()
        except pendulum.parsing.exceptions.ParserError:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a date before today."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a date before today."


class after_today(BaseValidation):
    def __init__(self, validations, tz="Universal", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.tz = tz

    def passes(self, attribute, key, dictionary):
        import pendulum

        try:
            return pendulum.parse(attribute, tz=self.tz) >= pendulum.yesterday()
        except pendulum.parsing.exceptions.ParserError:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a date after today."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a date after today."


class is_past(BaseValidation):
    def __init__(self, validations, tz="Universal", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.tz = tz

    def passes(self, attribute, key, dictionary):
        import pendulum

        try:
            return pendulum.parse(attribute, tz=self.tz).is_past()
        except pendulum.parsing.exceptions.ParserError:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a time in the past."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a time in the past."


class is_future(BaseValidation):
    def __init__(self, validations, tz="Universal", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.tz = tz

    def passes(self, attribute, key, dictionary):
        import pendulum

        try:
            return pendulum.parse(attribute, tz=self.tz).is_future()
        except pendulum.parsing.exceptions.ParserError:
            return False

    def message(self, attribute):
        return f"The {attribute} must be a time in the past."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a time in the past."


class email(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return re.compile(
            r"^[^.][^@]*@([?)[a-zA-Z0-9-.])+.([a-zA-Z]{2,3}|[0-9]{1,3})(]?)$"
        ).match(attribute)

    def message(self, attribute):
        return f"The {attribute} must be a valid email address."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a valid email address."


class matches(BaseValidation):
    def __init__(self, validations, match, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.match = match

    def passes(self, attribute, key, dictionary):
        return attribute == dictionary[self.match]

    def message(self, attribute):
        return f"The {attribute} must match {self.match}."

    def negated_message(self, attribute):
        return f"The {attribute} must not match {self.match}."


class exists(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return key in dictionary

    def message(self, attribute):
        return f"The {attribute} must exist."

    def negated_message(self, attribute):
        return f"The {attribute} must not exist."


def resolve_model_or_table(string):
    if "." not in string:
        return string, None
    model_name = string.split(".")[-1]
    model_class = Loader.get_object(string, model_name)
    table = model_class().get_table_name()
    return table, model_class


class exists_in_db(BaseValidation):
    """A record with field equal to the given value should exists in the table/model specified."""

    def __init__(
        self,
        validations,
        table_or_model,
        column=None,
        connection="default",
        messages={},
        raises={},
    ):
        super().__init__(validations, messages=messages, raises=raises)
        self.connection = config("database.db").get_query_builder(connection)
        self.column = column
        self.table, self.model = resolve_model_or_table(table_or_model)

    def passes(self, attribute, key, dictionary):
        column = self.column or key
        return self.connection.table(self.table).where(column, attribute).count()

    def message(self, attribute):
        return f"No record found in table {self.table} with the same {attribute}."

    def negated_message(self, attribute):
        return f"A record already exists in table {self.table} with the same {attribute}."


class unique_in_db(BaseValidation):
    """No record should exist for the field under validation within the given table/model."""

    def __init__(
        self,
        validations,
        table_or_model,
        column=None,
        connection="default",
        messages={},
        raises={},
    ):
        super().__init__(validations, messages=messages, raises=raises)
        self.connection = config("database.db").get_query_builder(connection)
        self.column = column
        self.table, self.model = resolve_model_or_table(table_or_model)

    def passes(self, attribute, key, dictionary):
        column = self.column or key
        count = self.connection.table(self.table).where(column, attribute).count()
        return count == 0

    def message(self, attribute):
        return f"A record already exists in table {self.table} with the same {attribute}."

    def negated_message(self, attribute):
        return f"A record should exist in table {self.table} with the same {attribute}."


class active_domain(BaseValidation):
    def passes(self, attribute, key, dictionary):
        import socket

        try:
            if "@" in attribute:
                # validation is for an email address
                return socket.gethostbyname(attribute.split("@")[1])

            return socket.gethostbyname(
                attribute.replace("https://", "")
                .replace("http://", "")
                .replace("www.", "")
            )
        except socket.gaierror:
            return False

    def message(self, attribute):
        return f"The {attribute} must be an active domain name."

    def negated_message(self, attribute):
        return f"The {attribute} must not be an active domain name."


class numeric(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return (
            all(str(value).isdigit() for value in attribute)
            if isinstance(attribute, list)
            else str(attribute).isdigit()
        )

    def message(self, attribute):
        return f"The {attribute} must be a numeric."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a numeric."


class is_list(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return isinstance(attribute, list)

    def message(self, attribute):
        return f"The {attribute} must be a list."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a list."


class string(BaseValidation):
    def passes(self, attribute, key, dictionary):
        if isinstance(attribute, list):
            return all(isinstance(attr, str) for attr in attribute)
        return isinstance(attribute, str)

    def message(self, attribute):
        return f"The {attribute} must be a string."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a string."


class none(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return attribute is None

    def message(self, attribute):
        return f"The {attribute} must be None."

    def negated_message(self, attribute):
        return f"The {attribute} must not be None."


class length(BaseValidation):
    def __init__(self, validations, min=0, max=False, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        if isinstance(min, str) and ".." in min:
            self.min = int(min.split("..")[0])
            self.max = int(min.split("..")[1])
        else:
            self.min = min
            self.max = max

    def passes(self, attribute, key, dictionary):
        if not hasattr(attribute, "__len__"):
            attribute = str(attribute)
        if self.max:
            return len(attribute) >= self.min and len(attribute) <= self.max
        else:
            return len(attribute) >= self.min

    def message(self, attribute):
        if self.min and not self.max:
            return f"The {attribute} must be at least {self.min} characters."
        else:
            return f"The {attribute} length must be between {self.min} and {self.max}."

    def negated_message(self, attribute):
        if self.min and not self.max:
            return f"The {attribute} must be {self.max} characters maximum."
        else:
            return f"The {attribute} length must not be between {self.min} and {self.max}."


class in_range(BaseValidation):
    def __init__(self, validations, min=1, max=255, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.min = min
        self.max = max

    def passes(self, attribute, key, dictionary):

        attribute = str(attribute)

        if attribute.isalpha():
            return False

        if "." in attribute:
            try:
                attribute = float(attribute)
            except Exception:
                pass

        elif attribute.isdigit():
            attribute = int(attribute)

        return attribute >= self.min and attribute <= self.max

    def message(self, attribute):
        return f"The {attribute} must be between {self.min} and {self.max}."

    def negated_message(self, attribute):
        return f"The {attribute} must not be between {self.min} and {self.max}."


class equals(BaseValidation):
    def __init__(self, validations, value="", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.value = value

    def passes(self, attribute, key, dictionary):
        return attribute == self.value

    def message(self, attribute):
        return f"The {attribute} must be equal to {self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} must not be equal to {self.value}."


class contains(BaseValidation):
    def __init__(self, validations, value="", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.value = value

    def passes(self, attribute, key, dictionary):
        return self.value in attribute

    def message(self, attribute):
        return f"The {attribute} must contain {self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} must not contain {self.value}."


class is_in(BaseValidation):
    def __init__(self, validations, value="", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.value = value

    def passes(self, attribute, key, dictionary):
        return attribute in self.value

    def message(self, attribute):
        return f"The {attribute} must contain an element in {self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} must not contain an element in {self.value}."


class greater_than(BaseValidation):
    def __init__(self, validations, value="", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.value = value

    def passes(self, attribute, key, dictionary):
        return attribute > self.value

    def message(self, attribute):
        return f"The {attribute} must be greater than {self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} must be greater than {self.value}."


class less_than(BaseValidation):
    def __init__(self, validations, value="", messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.value = value

    def passes(self, attribute, key, dictionary):
        return attribute < self.value

    def message(self, attribute):
        return f"The {attribute} must be less than {self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} must not be less than {self.value}."


class strong(BaseValidation):
    def __init__(
        self,
        validations,
        length=8,
        uppercase=2,
        numbers=2,
        special=2,
        breach=False,
        messages={},
        raises={},
    ):
        super().__init__(validations, messages=messages, raises=raises)
        self.length = length
        self.uppercase = uppercase
        self.numbers = numbers
        self.special = special
        self.breach = breach
        self.length_check = True
        self.uppercase_check = True
        self.numbers_check = True
        self.special_check = True
        self.breach_check = True

    def passes(self, attribute, key, dictionary):
        all_clear = True

        if len(attribute) < self.length:
            all_clear = False
            self.length_check = False

        if self.uppercase != 0:
            uppercase = sum(1 for letter in attribute if letter.isupper())
            if uppercase < self.uppercase:
                self.uppercase_check = False
                all_clear = False

        if self.numbers != 0:
            numbers = sum(bool(letter.isdigit()) for letter in attribute)
            if numbers < self.numbers:
                self.numbers_check = False
                all_clear = False

        if self.breach:
            try:
                from pwnedapi import Password
            except ImportError:
                raise ImportError(
                    "Checking for breaches requires the 'pwnedapi' library. Please install it with 'pip install pwnedapi'"
                )

            password = Password(attribute)
            if password.is_pwned():
                self.breach_check = False
                all_clear = False

        if (
            self.special != 0
            and len(re.findall("[^A-Za-z0-9]", attribute)) < self.special
        ):
            self.special_check = False
            all_clear = False

        return all_clear

    def message(self, attribute):
        message = []
        if not self.length_check:
            message.append(
                f"The {attribute} field must be {self.length} characters in length"
            )


        if not self.uppercase_check:
            message.append(
                f"The {attribute} field must have {self.uppercase} uppercase letters"
            )


        if not self.special_check:
            message.append(
                f"The {attribute} field must have {self.special} special characters"
            )


        if not self.numbers_check:
            message.append(f"The {attribute} field must have {self.numbers} numbers")

        if not self.breach_check:
            message.append(
                f"The {attribute} field has been breached in the past. Try another {attribute}"
            )


        return message

    def negated_message(self, attribute):
        return f"The {attribute} must not be less than {self.value}."


class isnt(BaseValidation):
    def __init__(self, *rules, messages={}, raises={}):
        super().__init__(rules)

    def handle(self, dictionary):
        for rule in self.validations:
            rule.negate().handle(dictionary)
            self.errors.update(rule.errors)


class does_not(BaseValidation):
    def __init__(self, *rules, messages={}, raises={}):
        super().__init__(rules)
        self.should_run_then = True

    def handle(self, dictionary):
        self.dictionary = dictionary
        errors = False
        for rule in self.validations:
            if rule.handle(dictionary):
                errors = True

        if not errors:
            for rule in self.then_rules:
                if not rule.handle(dictionary):
                    self.errors.update(rule.errors)

    def then(self, *rules):
        self.then_rules = rules
        return self


class when(BaseValidation):
    def __init__(self, *rules, messages={}, raises={}):
        super().__init__(rules)
        self.should_run_then = True

    def handle(self, dictionary):
        self.dictionary = dictionary
        errors = False
        for rule in self.validations:
            if rule.handle(dictionary):
                errors = True

        if errors:
            for rule in self.then_rules:
                if not rule.handle(dictionary):
                    self.errors.update(rule.errors)

    def then(self, *rules):
        self.then_rules = rules
        return self


class truthy(BaseValidation):
    def passes(self, attribute, key, dictionary):
        return attribute

    def message(self, attribute):
        return f"The {attribute} must be a truthy value."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a truthy value."


class json(BaseValidation):
    def passes(self, attribute, key, dictionary):
        import json as json_module

        try:
            return json_module.loads(str(attribute))
        except (TypeError, json_module.decoder.JSONDecodeError):
            return False

    def message(self, attribute):
        return f"The {attribute} must be a valid JSON."

    def negated_message(self, attribute):
        return f"The {attribute} must not be a valid JSON."


class phone(BaseValidation):
    def __init__(self, *rules, pattern="123-456-7890", messages={}, raises={}):
        super().__init__(rules, messages={}, raises={})
        # 123-456-7890
        # (123)456-7890
        self.pattern = pattern

    def passes(self, attribute, key, dictionary):
        if self.pattern == "(123)456-7890":
            return re.compile(r"^\(\w{3}\)\w{3}\-\w{4}$").match(attribute)
        elif self.pattern == "123-456-7890":
            return re.compile(r"^\w{3}\-\w{3}\-\w{4}$").match(attribute)

    def message(self, attribute):
        if self.pattern == "(123)456-7890":
            return f"The {attribute} must be in the format (XXX)XXX-XXXX."
        elif self.pattern == "123-456-7890":
            return f"The {attribute} must be in the format XXX-XXX-XXXX."

    def negated_message(self, attribute):
        if self.pattern == "(123)456-7890":
            return f"The {attribute} must not be in the format (XXX)XXX-XXXX."
        elif self.pattern == "123-456-7890":
            return f"The {attribute} must not be in the format XXX-XXX-XXXX."


class confirmed(BaseValidation):
    def passes(self, attribute, key, dictionary):
        if key in dictionary and f"{key}_confirmation" in dictionary:
            return dictionary[key] == dictionary[f"{key}_confirmation"]
        return False

    def message(self, attribute):
        return f"The {attribute} confirmation does not match."

    def negated_message(self, attribute):
        return f"The {attribute} confirmation matches."


class regex(BaseValidation):
    def __init__(self, validations, pattern, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.pattern = pattern

    def passes(self, attribute, key, dictionary):
        return re.compile(f"{self.pattern}").match(attribute)

    def message(self, attribute):
        return f"The {attribute} does not match pattern {self.pattern} ."

    def negated_message(self, attribute):
        return f"The {attribute} matches pattern {self.pattern} ."


def parse_size(size):
    """Parse humanized size into bytes"""
    from hfilesize import FileSize

    return FileSize(size, case_sensitive=False)


class BaseFileValidation(BaseValidation):
    def __init__(self, validations, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.file_check = True
        self.size_check = True
        self.mimes_check = True
        self.all_clear = True

    def passes(self, attribute, key, dictionary):
        if not os.path.isfile(attribute):
            self.file_check = False
            return False
        if self.size:
            file_size = os.path.getsize(attribute)
            if file_size > self.size:
                self.size_check = False
                self.all_clear = False
        if self.allowed_extensions:
            mimetype, encoding = mimetypes.guess_type(attribute)
            if mimetype not in self.allowed_mimetypes:
                self.mimes_check = False
                self.all_clear = False
        return self.all_clear


class file(BaseFileValidation):
    def __init__(self, validations, size=False, mimes=False, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.size = parse_size(size)

        # parse allowed extensions to a list of mime types
        self.allowed_extensions = mimes
        if mimes:
            self.allowed_mimetypes = list(
                map(lambda mt: mimetypes.types_map.get(f".{mt}", None), mimes)
            )

    def message(self, attribute):
        messages = []
        if not self.file_check:
            messages.append(f"The {attribute} is not a valid file.")

        if not self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size exceeds {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )
        if not self.mimes_check:
            messages.append(
                f'The {attribute} mime type is not valid. Allowed formats are {",".join(self.allowed_extensions)}.'
            )


        return messages

    def negated_message(self, attribute):
        messages = []
        if self.file_check:
            messages.append(f"The {attribute} is a valid file.")
        if self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size is less or equal than {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )
        if self.mimes_check:
            messages.append(
                f'The {attribute} mime type is in {",".join(self.allowed_extensions)}.'
            )

        return messages


class image(BaseFileValidation):
    def __init__(self, validations, size=False, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.size = parse_size(size)
        image_mimetypes = {
            ext: mimetype
            for ext, mimetype in mimetypes.types_map.items()
            if mimetype.startswith("image")
        }
        self.allowed_extensions = list(image_mimetypes.keys())
        self.allowed_mimetypes = list(image_mimetypes.values())

    def message(self, attribute):
        messages = []
        if not self.file_check:
            messages.append(f"The {attribute} is not a valid file.")

        if not self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size exceeds {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )

        if not self.mimes_check:
            messages.append(
                f'The {attribute} file is not a valid image. Allowed formats are {",".join(self.allowed_extensions)}.'
            )


        return messages

    def negated_message(self, attribute):
        messages = []
        if self.file_check:
            messages.append(f"The {attribute} is a valid file.")
        if self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size is less or equal than {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )

        if self.mimes_check:
            messages.append(f"The {attribute} file is a valid image.")

        return messages


class video(BaseFileValidation):
    def __init__(self, validations, size=False, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.size = parse_size(size)

        video_mimetypes = {
            ext: mimetype
            for ext, mimetype in mimetypes.types_map.items()
            if mimetype.startswith("video")
        }

        self.allowed_extensions = list(video_mimetypes.keys())
        self.allowed_mimetypes = list(video_mimetypes.values())

    def message(self, attribute):
        messages = []
        if not self.file_check:
            messages.append(f"The {attribute} is not a valid file.")

        if not self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size exceeds {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )

        if not self.mimes_check:
            messages.append(
                f'The {attribute} file is not a valid video. Allowed formats are {",".join(self.allowed_extensions)}.'
            )


        return messages

    def negated_message(self, attribute):
        messages = []
        if self.file_check:
            messages.append(f"The {attribute} is a valid file.")

        if self.size_check:
            from hfilesize import FileSize

            messages.append(
                "The {} file size is less or equal than {:.02fH}.".format(
                    attribute, FileSize(self.size)
                )
            )

        if self.mimes_check:
            messages.append(f"The {attribute} file is a valid video.")

        return messages


class postal_code(BaseValidation):
    def __init__(self, validations, locale, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        from .resources.postal_codes import PATTERNS

        self.locales = []
        self.patterns = []
        self.patterns_example = []
        self.locales = locale.split(",")

        for locale in self.locales:
            pattern_dict = PATTERNS.get(locale, None)
            if pattern_dict is None or pattern_dict["pattern"] is None:
                raise NotImplementedError(
                    f"Unsupported country code {locale}. Check that it is a ISO 3166-1 country code or open a PR to require support of this country code."
                )

            self.patterns.append(pattern_dict["pattern"])
            self.patterns_example.append(pattern_dict["example"])

    def passes(self, attribute, key, dictionary):
        return any(
            re.compile(f"{pattern}").match(attribute) for pattern in self.patterns
        )

    def message(self, attribute):
        return f'The {attribute} is not a valid {",".join(self.locales)} postal code. Valid {"examples are" if len(self.locales) > 1 else "example is"} {",".join(self.patterns_example)}.'

    def negated_message(self, attribute):
        return f"The {attribute} is a valid {self.locale} postal code."


class different(BaseValidation):
    """The field under validation must be different than an other given field."""

    def __init__(self, validations, other_field, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.other_field = other_field

    def passes(self, attribute, key, dictionary):
        other_value = dictionary.get(self.other_field, None)
        return attribute != other_value

    def message(self, attribute):
        return f"The {attribute} value must be different than {self.other_field} value."

    def negated_message(self, attribute):
        return f"The {attribute} value be the same as {self.other_field} value."


class uuid(BaseValidation):
    """The field under validation must be a valid UUID. The UUID version standard
    can be precised (1,3,4,5)."""

    def __init__(self, validations, version=4, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.version = version
        self.uuid_type = "UUID"
        if version:
            self.uuid_type = "UUID {0}".format(self.version)

    def passes(self, attribute, key, dictionary):
        from uuid import UUID

        try:
            uuid_value = UUID(str(attribute))
            return uuid_value.version == int(self.version)
        except ValueError:
            return False

    def message(self, attribute):
        return f"The {attribute} value must be a valid {self.uuid_type}."

    def negated_message(self, attribute):
        return f"The {attribute} value must not be a valid {self.uuid_type}."


class required_if(BaseValidation):
    """The field under validation must be present and not empty only
    if an other field has a given value."""

    def __init__(self, validations, other_field, value, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        self.other_field = other_field
        self.value = value

    def passes(self, attribute, key, dictionary):
        if dictionary.get(self.other_field, None) == self.value:
            return required.passes(self, attribute, key, dictionary)

        return True

    def message(self, attribute):
        return f"The {attribute} is required because {self.other_field}={self.value}."

    def negated_message(self, attribute):
        return f"The {attribute} is not required because {self.other_field}={self.value} or {self.other_field} is not present."


class required_with(BaseValidation):
    """The field under validation must be present and not empty only
    if any of the other specified fields are present."""

    def __init__(self, validations, other_fields, messages={}, raises={}):
        super().__init__(validations, messages=messages, raises=raises)
        if not isinstance(other_fields, list):
            if "," in other_fields:
                self.other_fields = other_fields.split(",")
            else:
                self.other_fields = [other_fields]
        else:
            self.other_fields = other_fields

    def passes(self, attribute, key, dictionary):
        return next(
            (
                required.passes(self, attribute, key, dictionary)
                for field in self.other_fields
                if field in dictionary
            ),
            True,
        )

    def message(self, attribute):
        fields = ",".join(self.other_fields)
        return "The {} is required because {} is present.".format(
            attribute,
            f"one in {fields}"
            if len(self.other_fields) > 1
            else self.other_fields[0],
        )

    def negated_message(self, attribute):
        return f'The {attribute} is not required because {"none of" if len(self.other_fields) > 1 else ""} {",".join(self.other_fields)} is not present.'


class distinct(BaseValidation):
    """When working with list, the field under validation must not have any
    duplicate values."""

    def passes(self, attribute, key, dictionary):
        # check if list contains duplicates
        return len(set(attribute)) == len(attribute)

    def message(self, attribute):
        return f"The {attribute} field has duplicate values."

    def negated_message(self, attribute):
        return f"The {attribute} field has only different values."


class Validator:
    def __init__(self):
        pass

    def validate(self, dictionary, *rules):
        rule_errors = {}
        try:
            for rule in rules:
                if isinstance(rule, str):
                    rule = self.parse_string(rule)
                    # continue
                elif isinstance(rule, dict):
                    rule = self.parse_dict(rule, dictionary, rule_errors)
                    continue

                elif inspect.isclass(rule) and isinstance(rule(), RuleEnclosure):
                    rule_errors |= self.run_enclosure(rule(), dictionary)
                    continue

                rule.handle(dictionary)
                for error, message in rule.errors.items():
                    if error not in rule_errors:
                        rule_errors[error] = message
                    else:
                        messages = rule_errors[error]
                        messages += message
                        rule_errors[error] = messages
                rule.reset()
            return MessageBag(rule_errors)

        except Exception as e:
            e.errors = rule_errors
            raise e

        return MessageBag(rule_errors)

    def parse_string(self, rule):
        rule, parameters = rule.split(":")[0], rule.split(":")[1].split(",")
        return ValidationFactory().registry[rule](parameters)

    def parse_dict(self, rule, dictionary, rule_errors):
        for value, rules in rule.items():
            for rule in rules.split("|"):
                rule, args = rule.split(":")[0], rule.split(":")[1:]
                rule = ValidationFactory().registry[rule](value, *args)

                rule.handle(dictionary)
                for error, message in rule.errors.items():
                    if error not in rule_errors:
                        rule_errors.update({error: message})
                    else:
                        messages = rule_errors[error]
                        messages += message
                        rule_errors.update({error: messages})

    def run_enclosure(self, enclosure, dictionary):
        rule_errors = {}
        for rule in enclosure.rules():
            rule.handle(dictionary)
            for error, message in rule.errors.items():
                if error not in rule_errors:
                    rule_errors[error] = message
                else:
                    messages = rule_errors[error]
                    messages += message
                    rule_errors[error] = messages
            rule.reset()
        return rule_errors

    def extend(self, key, obj=None):
        if isinstance(key, dict):
            self.__dict__.update(key)
            return self

        self.__dict__.update({key: obj})
        return self

    def register(self, *cls):
        for obj in cls:
            self.__dict__.update({obj.__name__: obj})
            ValidationFactory().register(obj)


class ValidationFactory:

    registry = {}

    def __init__(self):
        self.register(
            accepted,
            active_domain,
            after_today,
            before_today,
            confirmed,
            contains,
            date,
            does_not,
            different,
            distinct,
            equals,
            email,
            exists,
            exists_in_db,
            file,
            greater_than,
            image,
            in_range,
            is_future,
            is_in,
            isnt,
            is_list,
            is_past,
            ip,
            json,
            length,
            less_than,
            matches,
            none,
            numeric,
            one_of,
            phone,
            postal_code,
            regex,
            required,
            required_if,
            required_with,
            string,
            strong,
            timezone,
            truthy,
            unique_in_db,
            uuid,
            video,
            when,
        )

    def register(self, *cls):
        for obj in cls:
            self.registry.update({obj.__name__: obj})
