# Generated by Django 2.1.4 on 2018-12-08 21:05

from django.conf import settings
from django.core.files.storage import default_storage
from django.db import migrations
from django_ca import ca_settings
from django_ca.utils import write_private_file
import os
#import stat


def migrate_data(apps, schema_editor):
    CertificateAuthority = apps.get_model("django_ca", "CertificateAuthority")

    # Check if current CA_DIR contains BASE_DIR
    if os.path.isabs(ca_settings.CA_DIR):
        if os.path.commonpath([ca_settings.CA_DIR, settings.BASE_DIR]) == settings.BASE_DIR:
            prefix = os.path.relpath(ca_settings.CA_DIR, settings.BASE_DIR)
    else:
        prefix = ca_settings.CA_DIR

    # Move keys from CAs
        # Move all files to the storage
        for ca in CertificateAuthority.objects.all():
            if len(ca.private_key_path.name) > 0:
                # Previous versions stored absolute paths
                key_path = ca.private_key_path.name
                # Get new path using storage
                base_name = os.path.join(prefix, os.path.basename(ca.private_key_path.name))
                # Update the key path with the new location
                ca.private_key_path = base_name
                # Store
                ca.save()

                # Check if the key is at same location or not
                if not default_storage.exists(base_name):
                    # Key is not at the same location. Make a copy to the storage
                    # Read the key
                    with open(key_path, 'rb') as stream:
                        key_pem = stream.read()
                    write_private_file(base_name, key_pem)
                    # Uncomment to Remove old files
                    #os.chmod(key_path, stat.S_IWRITE)
                    #os.remove(key_path)


class Migration(migrations.Migration):

    dependencies = [
        ('django_ca', '0011_auto_20181208_0031'),
    ]

    operations = [
        migrations.RunPython(migrate_data),
    ]