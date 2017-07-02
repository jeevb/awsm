import dateutil.parser

from prettytable import PrettyTable


class BaseTable(PrettyTable):
    columns = None

    def __init__(self, skip_tags=None):
        super(BaseTable, self).__init__()
        # Temporary storage for stream data
        self._data = []

        # Tags to keep track of
        self._tags = set()

        # Skip these tags
        self._skip_tags = skip_tags or set()
        # Skip tags that are already field names
        for f in self.get_columns():
            self._skip_tags.add(f)

    @property
    def data(self):
        return self._data

    def get_columns(self):
        assert self.columns is not None, (
            '%r should either include a `columns` attribute, '
            'or override the `get_columns()` method.'
            % self.__class__.__name__
        )

        return list(self.columns)

    def load_stream(self, stream):
        for elem in stream:
            self.add_elem(elem)

        self.field_names = (
            self.get_columns() +
            sorted('tag:{}'.format(t) for t in self._tags)
        )
        for row in self._data:
            self.add_row([row.get(f, '') for f in self.field_names])

    def get_string(self, *args, **kwargs):
        self.align = 'l'
        self.border = False
        self._set_columns_style()
        self.header_style = 'upper'
        self.right_padding_width = 4
        return super(BaseTable, self).get_string(*args, **kwargs)


class InstanceTable(BaseTable):
    columns = ('Name', 'ID', 'Type', 'State', 'Public DNS',)

    def add_elem(self, elem):
        data = {
            'ID': elem['InstanceId'],
            'Type': elem['InstanceType'],
            'State': elem['State']['Name'],
            'Public DNS': elem['PublicDnsName']
        }

        for tag in elem['Tags']:
            key = tag['Key']
            if key not in self._skip_tags:
                self._tags.add(key)
                key = 'tag:{}'.format(key)

            # Don't override field values
            if key not in data:
                data[key] = tag['Value']

        self._data.append(data)


class VolumeTable(BaseTable):
    columns = ('Name', 'ID', 'Size', 'Type', 'Snapshot', 'State', 'Instance',)

    def add_elem(self, elem):
        data = {
            'ID': elem['VolumeId'],
            'Size': elem['Size'],
            'Type': elem['VolumeType'],
            'Snapshot': elem['SnapshotId'],
            'State': elem['State'],
        }

        attachments = elem['Attachments']
        if attachments:
            data['Instance'] = attachments[0]['InstanceId']

        for tag in elem['Tags']:
            key = tag['Key']
            if key not in self._skip_tags:
                self._tags.add(key)
                key = 'tag:{}'.format(key)

            # Don't override field values
            if key not in data:
                data[key] = tag['Value']

        self._data.append(data)
