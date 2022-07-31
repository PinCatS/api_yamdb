import django_filters

from reviews.models import Title


class TitleFilter(django_filters.FilterSet):
    """
    Filters by name, year, category and genre.
    Category and genre are ForeignKeys. Thus to keep genre and category
    filters name but filter by their slug field, we override filter here.
    Also name filter is expected to use 'icontains' lookup instead of
    'exact' which is default.
    """

    category = django_filters.CharFilter(field_name='category__slug')
    genre = django_filters.CharFilter(field_name='genre__slug')
    name = django_filters.CharFilter(
        field_name='name', lookup_expr='icontains'
    )

    class Meta:
        model = Title
        fields = (
            'name',
            'year',
            'category',
            'genre',
        )
