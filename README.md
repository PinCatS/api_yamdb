# YaMDb - API для сбора отзывов пользователей на произведения
Итоговый командный проект модуля *"API: интерфейс взаимодействия программ"* курса "Python-разработчик плюс" от Яндекс.Практикум в котором необходимо было разработать API для собора отзывов на произведения.

## Технологии
* Django Rest Framework
* JWT based authorization (SimpleJWT)
* Python
* Git

## Как запустить проект на локальном компьютере
1. Клонируйте проект
2. Создайте виртуальное окружение в корневой папке проекта: `python3 -m venv venv`
3. Активируйте виртуальное окружение: `source venv/bin/activate command`
4. Обновите pip до последней версии: `python3 -m pip install --upgrade pip command`
5. Установите необходимые зависимости: `pip install -r requirements.txt command`
6. Создайте миграции: `python3 manage.py makemigrations`
7. Примените миграции: `python3 manage.py migrate`
8. Импортируйте тестовые данные: `python3 manage.py importdata` (см. ниже детали работы команды)
9. Создайте суперюзера (если хотите иметь доступ к админке): `python3 manage.py createsuperuser`
9. Запустите проект: `python3 manage.py runserver`

По адресу `http://127.0.0.1:8000/redoc/` доступна документация по API

По адресу `http://127.0.0.1:8000/admin/` находится админка с основными моделями

## Импортирование тестовых данных
Данные в csv формате можно импортировать в БД через manage.py команду `python3 manage.py importdata`

Перед тем как выполнить команду, необходимо
1. В `settings.py` указать путь к папке с тестовыми данными через переменную `TEST_DATA_DIR`
```Python
TEST_DATA_DIR = os.path.join(BASE_DIR, 'static', 'data')
```
2. Указать список моделей в `Reviews.management.commands.importdata`, для которых необходимо импортировать данные.
```Python
from Reviews.management.base import ImportDataBaseCommand
from Reviews.models import Category, Genre, GenreTitle, Title
from Users.models import User


class Command(ImportDataBaseCommand):
    models = (Category, Genre, Title, GenreTitle, User)
```

Порядок моделей важен, так как некоторые модели могут ссылаться на существующие записи в других моделях.

Имена файлов должны соответствовать именам моделей в snake case формате.
Команда преобразует имя модели из camel case в snake case и переводит буквы в нижней регистр.
Например, для модели `GenreTitle`, команда будет искать файл `genre_title.csv` в директории `TEST_DATA_DIR`

Данные должны быть в формате csv с заголовком на первой строке. Заголовки должны соответствовать именам полей модели.

```CSV
id,name,slug
1,Фильм,movie
2,Книга,book
3,Музыка,music
```

Если у модели есть поля ссылающиеся на другую модель (ForeignKey), то команда определит это, сделает запрос по id на ссылаемый объект и уже этот объект будет использован при создании.

```CSV
id,name,year,category
1,Побег из Шоушенка,1994,1
```

Заголовок `category` это поле в модели `Title`:

```Python
class Title(models.Model):
    #...
    category = models.ForeignKey(
        Category,
        related_name='categories',
        on_delete=models.SET_NULL,
        null=True,
    )
```

При добавлении записи в таблицу Title, команда сначала сделает запрос
```Python
obj = Category.objects.get(pk=1)
```
и затем выдаст команду:

```Python
Title.objects.get_or_create(...,category=obj,...)
```

Если таблица модели содержит id ссылаемого объекта, то необходимо добавить суффикс '_id' к наименованию заголовка.
В этом случае в запросе на создание будет использован id ссылаемого объекта напрямую.

```CSV
id,title_id,genre_id
1,1,1
```

Несмотря на то, что в модели GenreTitle поля genre и title имеют тип ForeignKey, создание объекта в таблице должно быть напрямую через id. Поэтому в csv выше добавлены суффиксы '_id'.

```Python
class GenreTitle(models.Model):
    genre = models.ForeignKey(Genre, on_delete=models.CASCADE)
    title = models.ForeignKey(Title, on_delete=models.CASCADE)
```

В этом случае, команда не будет делать запрос в `Genre` и `Title`, а напрямую выполнит:

```Python
GenreTitle.objects.get_or_create(title_id='1',genre_id='1')
```

После того как команда отработала, выводится отчёт об импортированных записях:

```
============================================================
ЗАПИСЕЙ ДОБАВЛЕНО

Category       :   3
Genre          :  15
Title          :  32
GenreTitle     :  42
User           :   5
============================================================
```

Если передать аргумент verbosity > 1, то команда будет выводить содержимое добавляемых записей.

`python3 manage.py importdata -v 2`

```Python
Добавляется запись {'id': '1', 'title_id': '1', 'genre_id': '1'} в таблицу модели GenreTitle
Добавляется запись {'id': '2', 'title_id': '2', 'genre_id': '1'} в таблицу модели GenreTitle
Добавляется запись {'id': '3', 'title_id': '3', 'genre_id': '1'} в таблицу модели GenreTitle
```
## Авторы
* Василиса Немоляева
* Кирилл Яснов
* Сергей Ли
