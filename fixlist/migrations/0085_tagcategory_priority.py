from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0084_fixlistsnippet_trigger_tags'),
    ]

    operations = [
        migrations.AddField(
            model_name='tagcategory',
            name='priority',
            field=models.PositiveSmallIntegerField(
                default=5, validators=[MinValueValidator(0), MaxValueValidator(10)],
            ),
        ),
    ]
