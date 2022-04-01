"""vaitp_dataset dataset."""

import tensorflow_datasets as tfds


_DESCRIPTION = """

VAITP dataset
Custom injectable and vulnerable Python code dataset

"""


_CITATION = """
@ARTICLE {,
    author  = "Frédéric Bogaerts",
    title   = "vaitp-dataset",
    journal = "FCTUC",
    year    = "2022"
}
"""


class VaitpDataset(tfds.core.GeneratorBasedBuilder):
  """DatasetBuilder for vaitp_dataset dataset."""

  VERSION = tfds.core.Version('1.0.0')
  RELEASE_NOTES = {
      '1.0.0': 'Initial release.',
  }

  def _info(self) -> tfds.core.DatasetInfo:
    """Returns the dataset metadata."""
    # Specifies the tfds.core.DatasetInfo object
    return tfds.core.DatasetInfo(
        builder=self,
        description=_DESCRIPTION,
        features=tfds.features.FeaturesDict({
            # These are the features of the dataset
            'code': tfds.features.Text(),
            'label': tfds.features.ClassLabel(names=['injectable', 'vulnerable']),
        }),
        # Common (input, target) tuple from the
        # features. They'll be used if
        # `as_supervised=True` is `builder.as_dataset`.
        supervised_keys=('code', 'label'), 
        homepage='https://github.com/netpack/vaitp',
        citation=_CITATION,
    )

  def _split_generators(self, dl_manager: tfds.download.DownloadManager):
    """Returns SplitGenerators."""
    # Downloads the data and defines the splits
    path_vulnerable = dl_manager.download_and_extract('https://netpack.pt/vaitp/vaitp-dataset-injv-2022.tar.gz')

    # Returns the Dict[split names, Iterator[Key, Example]]
    path = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/"
    return {
        'code': self._generate_examples('./vaitp_dataset_code'),
    }

  def _generate_examples(self, path):
    """Yields examples."""
    # Yields python code (key, example) tuples from the dataset
    for f in path.glob('*.txt'):
      yield 'key', {
          'code': f,
          'label': 'pythoncodevaitp',
      }

