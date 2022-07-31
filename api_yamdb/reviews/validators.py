import datetime

from django.core.exceptions import ValidationError


def validate_not_future_year(value):
    """
    Validates incoming year to be less than or equal to current year.
    """
    todays_year = datetime.date.today().year
    if value > todays_year:
        raise ValidationError(
            f'Год выпуска {value} не может быть больше '
            f'текущего {todays_year}'
        )
    return value
