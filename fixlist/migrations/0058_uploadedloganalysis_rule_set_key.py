from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('fixlist', '0057_userprofile_rule_set_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedloganalysis',
            name='rule_set_key',
            field=models.CharField(db_index=True, default='shared', max_length=64),
        ),
        migrations.AlterField(
            model_name='uploadedloganalysis',
            name='upload',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='cached_analyses',
                to='fixlist.uploadedlog',
            ),
        ),
        migrations.AddConstraint(
            model_name='uploadedloganalysis',
            constraint=models.UniqueConstraint(
                fields=('upload', 'rule_set_key'),
                name='uploaded_log_analysis_unique_per_key',
            ),
        ),
    ]
