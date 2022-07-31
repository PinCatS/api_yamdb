import csv
import os
import re

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError
from django.db.models import ForeignKey


class ImportDataException(Exception):
    """Exception in case of importing data to db."""

    pass


class ImportDataBaseCommand(BaseCommand):
    help = 'Import csv data into db via Django ORM'
    models = ()

    _camel_2_snake_case = re.compile(r'(?<!^)(?=[A-Z])')

    def _get_filename_by_model_name(self, model_name) -> str:
        """
        Converts model name into a filename from which test data is imported.
        """
        snake_case_name = self._camel_2_snake_case.sub('_', model_name).lower()
        return os.path.join(settings.TEST_DATA_DIR, f'{snake_case_name}.csv')

    def _get_foreign_key_model(self, model, fieldname):
        """
        Returns None if not foreignkey, otherswise the relevant model.
        """
        field_object = model._meta.get_field(fieldname)
        if isinstance(field_object, ForeignKey):
            return field_object.remote_field.model
        return None

    def _build_db_record(self, model, row):
        """
        Takes row of data that corresponds to model table record data
        and converts it to record that can be passed to created record
        in a db table.

        row is an OrderedDict where key is a model field and value is a
        field value.

        The method checks if field is a ForeignKey field and if it is,
        it gets related object from db and assigns it as a value to the
        field. Exception is when field name ends with '_id', meaning that
        object id can be used to create record.
        If the field contains any other than ForeignKey field, it simply
        assigns the value.

        returns record which is a dict with fieldname and its value
        """
        record = {}
        for key, value in row.items():
            related_object = self._get_foreign_key_model(model, key)
            if related_object and not key.endswith('_id'):
                obj_instance = related_object.objects.get(pk=value)
                record[key] = obj_instance
            else:
                record[key] = value
        return record

    def _import_data(self, model, filename, verbosity) -> int:
        """
        Parses csv data from filename and creates db records for models.
        Returns number of records imported.
        """
        try:
            records_imported_count = 0
            with open(filename, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    record = self._build_db_record(model, row)
                    if verbosity > 1:
                        msg = (
                            f'Добавляется запись {record} в таблицу '
                            f'модели {model.__name__}'
                        )
                        self.stdout.write(self.style.SUCCESS(msg))
                    try:
                        model.objects.get(pk=record.get('id'))
                    except model.DoesNotExist:
                        model.objects.create(**record)
                    records_imported_count += 1
            return records_imported_count
        except FileNotFoundError:
            error_message = (
                f'Файл {filename} с тестовыми данными не был найден '
                f'для модели {model.__name__}.'
            )
            raise ImportDataException(error_message)
        except csv.Error as err:
            error_message = (
                f'Ошибка при парсинге файла {filename} с тестовыми данными '
                f'для модели {model.__name__}. Причина: {err}'
            )
            raise ImportDataException(error_message) from err
        except DatabaseError as err:
            error_message = (
                f'Ошибка при создание записи в таблице модели {model.__name__}'
                f' на основе тестовых данных из {filename}. '
                f'Причина: {err}'
            )
            raise ImportDataException(error_message) from err

    def display_summary(self, summary_data):
        """
        Display summary how many records for what models were imported so far.
        """
        BORDER = '=' * 60
        self.stdout.write(self.style.SUCCESS(BORDER))
        self.stdout.write(self.style.SUCCESS('ЗАПИСЕЙ ДОБАВЛЕНО\n'))
        for model_name, recs_count in summary_data.items():
            self.stdout.write(
                self.style.SUCCESS(f'{model_name:<15}: {recs_count:>3}')
            )
        self.stdout.write(self.style.SUCCESS(BORDER))

    def handle(self, *args, **options):
        """
        The method that exucutes main logic of importdata command.

        It runs through models, builds filename with csv data by modelname,
        parses csv data, determines fields and its type, build data record
        and uses it to get or create record in the model table.

        Note: it doesn't fail in case records are already in db.
        """

        if not self.models:
            self.stdout.write(
                self.style.WARNING(
                    'В списке models нет ни одной модли '
                    'для которой нужно импортировать данные'
                )
            )
            return

        summary_data = {model.__name__: 0 for model in self.models}

        for model in self.models:

            filename = self._get_filename_by_model_name(model.__name__)

            try:
                verbosity = options.get('verbosity', 1)
                records_imported_count = self._import_data(
                    model, filename, verbosity
                )
                summary_data[model.__name__] = records_imported_count
            except ImportDataException as err:
                # show at least what were added so far
                self.display_summary(summary_data)
                raise CommandError(err) from err

        self.display_summary(summary_data)
