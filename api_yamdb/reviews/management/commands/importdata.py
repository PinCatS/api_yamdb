from reviews.management.base import ImportDataBaseCommand
from reviews.models import Category, Comment, Genre, GenreTitle, Review, Title
from users.models import User


class Command(ImportDataBaseCommand):
    models = (
        Category,
        Genre,
        Title,
        GenreTitle,
        User,
        Review,
        Comment,
    )
