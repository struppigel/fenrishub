from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0026_infectioncasenote'),
    ]

    operations = [
        migrations.AddField(
            model_name='infectioncasenote',
            name='anchor_log',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='pinned_notes',
                to='fixlist.infectioncaselog',
            ),
        ),
    ]
