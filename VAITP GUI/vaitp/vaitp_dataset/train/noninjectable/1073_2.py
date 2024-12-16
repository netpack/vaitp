.. include:: _contributors.rst

.. currentmodule:: sklearn

.. _release_notes_1_5:

===========
Version 1.5
===========

..
  -- UNCOMMENT WHEN 1.5.0 IS RELEASED --
  For a short description of the main highlights of the release, please refer to
  :ref:`sphx_glr_auto_examples_release_highlights_plot_release_highlights_1_5_0.py`.

.. include:: changelog_legend.inc

.. _changes_1_5:

Version 1.5.0
=============

**In Development**

Changed models
--------------

- |Efficiency| The subsampling in :class:`preprocessing.QuantileTransformer` is now
  more efficient for dense arrays but the fitted quantiles and the results of
  `transform` may be slightly different than before (keeping the same statistical
  properties).
  :pr:`27344` by :user:`Xuefeng Xu <xuefeng-xu>`.

- |Enhancement| :class:`decomposition.PCA`, :class:`decomposition.SparsePCA`
  and :class:`decomposition.TruncatedSVD` now set the sign of the `components_`
  attribute based on the component values instead of using the transformed data
  as reference. This change is needed to be able to offer consistent component
  signs across all `PCA` solvers, including the new
  `svd_solver="covariance_eigh"` option introduced in this release.

Support for Array API
---------------------

Additional estimators and functions have been updated to include support for all
`Array API <https://data-apis.org/array-api/latest/>`_ compliant inputs.

See :ref:`array_api` for more details.

**Functions:**

- :func:`sklearn.metrics.r2_score` now supports Array API compliant inputs.
  :pr:`27904` by :user:`Eric Lindgren <elindgren>`, `Franck Charras <fcharras>`,
  `Olivier Grisel <ogrisel>` and `Tim Head <betatim>`.

**Classes:**

Support for building with Meson
-------------------------------

Meson is now supported as a build backend, see :ref:`Building from source
<install_bleeding_edge>` for more details.

:pr:`28040` by :user:`Loïc Estève <lesteve>`

TODO Fill more details before the 1.5 release, when the Meson story has settled down.

Metadata Routing
----------------

The following models now support metadata routing in one or more or their
methods. Refer to the :ref:`Metadata Routing User Guide <metadata_routing>` for
more details.

- |Feature| :class:`impute.IterativeImputer` now supports metadata routing in
  its `fit` method. :pr:`28187` by :user:`Stefanie Senger <StefanieSenger>`.

- |Feature| :class:`ensemble.BaggingClassifier` and :class:`ensemble.BaggingRegressor`
  now support metadata routing. The fit methods now
  accept ``**fit_params`` which are passed to the underlying estimators
  via their `fit` methods.
  :pr:`28432` by :user:`Adam Li <adam2392>` and :user:`Benjamin Bossan <BenjaminBossan>`.

- |Feature| :class:`linear_model.RidgeCV` and
  :class:`linear_model.RidgeClassifierCV` now support metadata routing in
  their `fit` method and route metadata to the underlying
  :class:`model_selection.GridSearchCV` object or the underlying scorer.
  :pr:`27560` by :user:`Omar Salman <OmarManzoor>`.

- |Feature| :class:`GraphicalLassoCV` now supports metadata routing in it's
  `fit` method and routes metadata to the CV splitter.
  :pr:`27566` by :user:`Omar Salman <OmarManzoor>`.

- |Feature| :class:`linear_model.RANSACRegressor` now supports metadata routing
  in its ``fit``, ``score`` and ``predict`` methods and route metadata to its
  underlying estimator's' ``fit``, ``score`` and ``predict`` methods.
  :pr:`28261` by :user:`Stefanie Senger <StefanieSenger>`.

- |Feature| :class:`ensemble.VotingClassifier` and
  :class:`ensemble.VotingRegressor` now support metadata routing and pass
  ``**fit_params`` to the underlying estimators via their `fit` methods.
  :pr:`27584` by :user:`Stefanie Senger <StefanieSenger>`.

- |Feature| :class:`pipeline.FeatureUnion` now supports metadata routing in its
  ``fit`` and ``fit_transform`` methods and route metadata to the underlying
  transformers' ``fit`` and ``fit_transform``. :pr:`28205` by :user:`Stefanie
  Senger <StefanieSenger>`.

- |Fix| Fix an issue when resolving default routing requests set via class
  attributes.
  :pr:`28435` by `Adrin Jalali`_.

- |Fix| Fix an issue when `set_{method}_request` methods are used as unbound
  methods, which can happen if one tries to decorate them.
  :pr:`28651` by `Adrin Jalali`_.

Changelog
---------

..
    Entries should be grouped by module (in alphabetic order) and prefixed with
    one of the labels: |MajorFeature|, |Feature|, |Efficiency|, |Enhancement|,
    |Fix| or |API| (see whats_new.rst for descriptions).
    Entries should be ordered by those labels (e.g. |Fix| after |Efficiency|).
    Changes not specific to a module should be listed under *Multiple Modules*
    or *Miscellaneous*.
    Entries should end with:
    :pr:`123456` by :user:`Joe Bloggs <joeongithub>`.
    where 123455 is the *pull request* number, not the issue number.

:mod:`sklearn.calibration`
..........................

- |Fix| Fixed a regression in :class:`calibration.CalibratedClassifierCV` where
  an error was wrongly raised with string targets. 
  :pr:`28843` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

:mod:`sklearn.cluster`
......................

- |FIX| Create copy of precomputed sparse matrix within the `fit` method of
  :class:`~cluster.OPTICS` to avoid in-place modification of the sparse matrix.
  :pr:`28491` by :user:`Thanh Lam Dang <lamdang2k>`.

- |Fix| :class:`cluster.HDBSCAN` now supports all metrics supported by
  :func:`sklearn.metrics.pairwise_distances` when `algorithm="brute"` or `"auto"`.
  :pr:`28664` by :user:`Manideep Yenugula <myenugula>`.

:mod:`sklearn.compose`
......................

- |Feature| A fitted :class:`compose.ColumnTransformer` now implements `__getitem__`
  which returns the fitted transformers by name. :pr:`27990` by `Thomas Fan`_.

- |Enhancement| :class:`compose.TransformedTargetRegressor` now raises an error in `fit`
  if only `inverse_func` is provided without `func` (that would default to identity)
  being explicitly set as well.
  :pr:`28483` by :user:`Stefanie Senger <StefanieSenger>`.

- |Fix| Fixed an bug in :class:`compose.ColumnTransformer` with `n_jobs > 1`, where the
  intermediate selected columns were passed to the transformers as read-only arrays.
  :pr:`28822` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

:mod:`sklearn.cross_decomposition`
..................................

- |API| Deprecates `Y` in favor of `y` in the methods fit, transform and inverse_transform of:
  :class:`cross_decomposition.PLSRegression`.
  :class:`cross_decomposition.PLSCanonical`,
  :class:`cross_decomposition.CCA`,
  and :class:`cross_decomposition.PLSSVD`.
  `Y` will be removed in version 1.7.
  :pr:`28604` by :user:`David Leon <davidleon123>`

:mod:`sklearn.datasets`
.......................

- |Enhancement| Adds optional arguments `n_retries` and `delay` to functions
  :func:`datasets.fetch_20newsgroups`,
  :func:`datasets.fetch_20newsgroups_vectorized`,
  :func:`datasets.fetch_california_housing`,
  :func:`datasets.fetch_covtype`,
  :func:`datasets.fetch_kddcup99`,
  :func:`datasets.fetch_lfw_pairs`,
  :func:`datasets.fetch_lfw_people`,
  :func:`datasets.fetch_olivetti_faces`,
  :func:`datasets.fetch_rcv1`,
  and :func:`datasets.fetch_species_distributions`.
  By default, the functions will retry up to 3 times in case of network failures.
  :pr:`28160` by :user:`Zhehao Liu <MaxwellLZH>` and :user:`Filip Karlo Došilović <fkdosilovic>`.

:mod:`sklearn.decomposition`
............................

- |Efficiency| :class:`decomposition.PCA` with `svd_solver="full"` now assigns
  a contiguous `components_` attribute instead of an non-contiguous slice of
  the singular vectors. When `n_components << n_features`, this can save some
  memory and, more importantly, help speed-up subsequent calls to the `transform`
  method by more than an order of magnitude by leveraging cache locality of
  BLAS GEMM on contiguous arrays.
  :pr:`27491` by :user:`Olivier Grisel <ogrisel>`.

- |Enhancement| :class:`~decomposition.PCA` now automatically selects the ARPACK solver
  for sparse inputs when `svd_solver="auto"` instead of raising an error.
  :pr:`28498` by :user:`Thanh Lam Dang <lamdang2k>`.

- |Enhancement| :class:`decomposition.PCA` now supports a new solver option
  named `svd_solver="covariance_eigh"` which offers an order of magnitude
  speed-up and reduced memory usage for datasets with a large number of data
  points and a small number of features (say, `n_samples >> 1000 >
  n_features`). The `svd_solver="auto"` option has been updated to use the new
  solver automatically for such datasets. This solver also accepts sparse input
  data.
  :pr:`27491` by :user:`Olivier Grisel <ogrisel>`.

- |Fix| :class:`decomposition.PCA` fit with `svd_solver="arpack"`,
  `whiten=True` and a value for `n_components` that is larger than the rank of
  the training set, no longer returns infinite values when transforming
  hold-out data.
  :pr:`27491` by :user:`Olivier Grisel <ogrisel>`.

:mod:`sklearn.dummy`
....................

- |Enhancement| :class:`dummy.DummyClassifier` and :class:`dummy.DummyRegressor` now
  have the `n_features_in_` and `feature_names_in_` attributes after `fit`.
  :pr:`27937` by :user:`Marco vd Boom <tvdboom>`.

:mod:`sklearn.ensemble`
.......................

- |Efficiency| Improves runtime of `predict` of
  :class:`ensemble.HistGradientBoostingClassifier` by avoiding to call `predict_proba`.
  :pr:`27844` by :user:`Christian Lorentzen <lorentzenchr>`.

- |Efficiency| :class:`ensemble.HistGradientBoostingClassifier` and
  :class:`ensemble.HistGradientBoostingRegressor` are now a tiny bit faster by
  pre-sorting the data before finding the thresholds for binning.
  :pr:`28102` by :user:`Christian Lorentzen <lorentzenchr>`.

:mod:`sklearn.feature_extraction`
.................................

- |Efficiency| :class:`feature_extraction.text.TfidfTransformer` is now faster
  and more memory-efficient by using a NumPy vector instead of a sparse matrix
  for storing the inverse document frequency.
  :pr:`18843` by :user:`Paolo Montesel <thebabush>`.

- |Enhancement| :class:`feature_extraction.text.TfidfTransformer` now preserves
  the data type of the input matrix if it is `np.float64` or `np.float32`.
  :pr:`28136` by :user:`Guillaume Lemaitre <glemaitre>`.

:mod:`sklearn.feature_selection`
................................

- |Enhancement| :func:`feature_selection.mutual_info_regression` and
  :func:`feature_selection.mutual_info_classif` now support `n_jobs` parameter.
  :pr:`28085` by :user:`Neto Menoci <netomenoci>` and
  :user:`Florin Andrei <FlorinAndrei>`.

- |Enhancement| The `cv_results_` attribute of :class:`feature_selection.RFECV` has
  a new key, `n_features`, containing an array with the number of features selected
  at each step.
  :pr:`28670` by :user:`Miguel Silva <miguelcsilva>`.

:mod:`sklearn.impute`
.....................

- |Enhancement| :class:`impute.SimpleImputer` now supports custom strategies
  by passing a function in place of a strategy name.
  :pr:`28053` by :user:`Mark Elliot <mark-thm>`.

:mod:`sklearn.inspection`
.........................

- |Fix| :meth:`inspection.DecisionBoundaryDisplay.from_estimator` no longer
  warns about missing feature names when provided a `polars.DataFrame`.
  :pr:`28718` by :user:`Patrick Wang <patrickkwang>`.

:mod:`sklearn.linear_model`
...........................

- |Enhancement| Solver `"newton-cg"` in :class:`linear_model.LogisticRegression` and
  :class:`linear_model.LogisticRegressionCV` now emits information when `verbose` is
  set to positive values.
  :pr:`27526` by :user:`Christian Lorentzen <lorentzenchr>`.

- |Fix| :class:`linear_model.ElasticNet`, :class:`linear_model.ElasticNetCV`,
  :class:`linear_model.Lasso` and :class:`linear_model.LassoCV` now explicitly don't
  accept large sparse data formats. :pr:`27576` by :user:`Stefanie Senger
  <StefanieSenger>`.

- |API| :class:`linear_model.RidgeCV` and :class:`linear_model.RidgeClassifierCV`
  will now allow `alpha=0` when `cv != None`, which is consistent with
  :class:`linear_model.Ridge` and :class:`linear_model.RidgeClassifier`.
  :pr:`28425` by :user:`Lucy Liu <lucyleeow>`.

- |Fix| :class:`linear_model.RidgeCV` and :class:`RidgeClassifierCV` correctly pass
  `sample_weight` to the underlying scorer when `cv` is None.
  :pr:`27560` by :user:`Omar Salman <OmarManzoor>`.

- |Fix| `n_nonzero_coefs_` attribute in :class:`linear_model.OrthogonalMatchingPursuit`
  will now always be `None` when `tol` is set, as `n_nonzero_coefs` is ignored in
  this case. :pr:`28557` by :user:`Lucy Liu <lucyleeow>`.

- |API| Passing `average=0` to disable averaging is deprecated in
  :class:`linear_model.PassiveAggressiveClassifier`,
  :class:`linear_model.PassiveAggressiveRegressor`,
  :class:`linear_model.SGDClassifier`, :class:`linear_model.SGDRegressor` and
  :class:`linear_model.SGDOneClassSVM`. Pass `average=False` instead.
  :pr:`28582` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

:mod:`sklearn.manifold`
.......................

- |API| Deprecates `n_iter` in favor of `max_iter` in :class:`manifold.TSNE`.
  `n_iter` will be removed in version 1.7. This makes :class:`manifold.TSNE`
  consistent with the rest of the estimators. :pr:`28471` by
  :user:`Lucy Liu <lucyleeow>`

:mod:`sklearn.metrics`
......................

- |Feature| :func:`metrics.pairwise_distances` accepts calculating pairwise distances
  for non-numeric arrays as well. This is supported through custom metrics only.
  :pr:`27456` by :user:`Venkatachalam N <venkyyuvy>`, :user:`Kshitij Mathur <Kshitij68>`
  and :user:`Julian Libiseller-Egger <julibeg>`.

- |Efficiency| Improve efficiency of functions :func:`~metrics.brier_score_loss`,
  :func:`~metrics.calibration_curve`, :func:`~metrics.det_curve`,
  :func:`~metrics.precision_recall_curve`,
  :func:`~metrics.roc_curve` when `pos_label` argument is specified.
  Also improve efficiency of methods `from_estimator`
  and `from_predictions` in :class:`~metrics.RocCurveDisplay`,
  :class:`~metrics.PrecisionRecallDisplay`, :class:`~metrics.DetCurveDisplay`,
  :class:`~calibration.CalibrationDisplay`.
  :pr:`28051` by :user:`Pierre de Fréminville <pidefrem>`.

- |Feature| :func:`sklearn.metrics.check_scoring` now returns a multi-metric scorer
  when `scoring` as a `dict`, `set`, `tuple`, or `list`. :pr:`28360` by `Thomas Fan`_.

- |Fix|:class:`metrics.classification_report` now shows only accuracy and not
  micro-average when input is a subset of labels.
  :pr:`28399` by :user:`Vineet Joshi <vjoshi253>`.

- |Fix| Fix OpenBLAS 0.3.26 dead-lock on Windows in pairwise distances
  computation. This is likely to affect neighbor-based algorithms.
  :pr:`28692` by :user:`Loïc Estève <lesteve>`.

- |API| :func:`metrics.precision_recall_curve` deprecated the keyword argument `probas_pred`
  in favor of `y_score`. `probas_pred` will be removed in version 1.7.
  :pr:`28092` by :user:`Adam Li <adam2392>`.

- |API| :func:`metrics.brier_score_loss` deprecated the keyword argument `y_prob`
  in favor of `y_proba`. `y_prob` will be removed in version 1.7.
  :pr:`28092` by :user:`Adam Li <adam2392>`.

- |API| For classifiers and classification metrics, labels encoded as bytes
  is deprecated and will raise an error in v1.7.
  :pr:`18555` by :user:`Kaushik Amar Das <cozek>`.

:mod:`sklearn.mixture`
......................

- |Fix| The `converged_` attribute of :class:`mixture.GaussianMixture` and
  :class:`mixture.BayesianGaussianMixture` now reflects the convergence status of
  the best fit whereas it was previously `True` if any of the fits converged.
  :pr:`26837` by :user:`Krsto Proroković <krstopro>`.

:mod:`sklearn.model_selection`
..............................

- |Enhancement| :term:`CV splitters <CV splitter>` that ignores the group parameter now
  raises a warning when groups are passed in to :term:`split`. :pr:`28210` by
  `Thomas Fan`_.

- |Fix| the ``cv_results_`` attribute (of :class:`model_selection.GridSearchCV`) now
  returns masked arrays of the appropriate NumPy dtype, as opposed to always returning
  dtype ``object``. :pr:`28352` by :user:`Marco Gorelli<MarcoGorelli>`.

- |Fix| :func:`sklearn.model_selection.train_test_score` works with Array API inputs.
  Previously indexing was not handled correctly leading to exceptions when using strict
  implementations of the Array API like CuPY.
  :pr:`28407` by :user:`Tim Head <betatim>`.

- |Enhancement| The HTML diagram representation of
  :class:`~model_selection.GridSearchCV`,
  :class:`~model_selection.RandomizedSearchCV`,
  :class:`~model_selection.HalvingGridSearchCV`, and
  :class:`~model_selection.HalvingRandomSearchCV` will show the best estimator when
  `refit=True`. :pr:`28722` by :user:`Yao Xiao <Charlie-XIAO>` and `Thomas Fan`_.

:mod:`sklearn.multioutput`
..........................

- |Enhancement| `chain_method` parameter added to :class:`multioutput.ClassifierChain`.
  :pr:`27700` by :user:`Lucy Liu <lucyleeow>`.

:mod:`sklearn.neighbors`
........................

- |Fix| Fixes :class:`neighbors.NeighborhoodComponentsAnalysis` such that
  `get_feature_names_out` returns the correct number of feature names.
  :pr:`28306` by :user:`Brendan Lu <brendanlu>`.

:mod:`sklearn.pipeline`
.......................

- |Feature| :class:`pipeline.FeatureUnion` can now use the
  `verbose_feature_names_out` attribute. If `True`, `get_feature_names_out`
  will prefix all feature names with the name of the transformer
  that generated that feature. If `False`, `get_feature_names_out` will not
  prefix any feature names and will error if feature names are not unique.
  :pr:`25991` by :user:`Jiawei Zhang <jiawei-zhang-a>`.

:mod:`sklearn.preprocessing`
............................

- |Enhancement| :class:`preprocessing.QuantileTransformer` and
  :func:`preprocessing.quantile_transform` now supports disabling
  subsampling explicitly.
  :pr:`27636` by :user:`Ralph Urlus <rurlus>`.

:mod:`sklearn.tree`
...................

- |Enhancement| Plotting trees in matplotlib via :func:`tree.plot_tree` now
  show a "True/False" label to indicate the directionality the samples traverse
  given the split condition.
  :pr:`28552` by :user:`Adam Li <adam2392>`.

:mod:`sklearn.utils`
....................

- |API| :data:`utils.IS_PYPY` is deprecated and will be removed in version 1.7.
  :pr:`28768` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

- |API| :func:`utils.tosequence` is deprecated and will be removed in version 1.7.
  :pr:`28763` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

- |API| :class:`utils.parallel_backend` and :func:`utils.register_parallel_backend` are
  deprecated and will be removed in version 1.7. Use `joblib.parallel_backend` and
  `joblib.register_parallel_backend` instead.
  :pr:`28847` by :user:`Jérémie du Boisberranger <jeremiedbb>`.

- |API| Raise informative warning message in :func:`type_of_target` when
  represented as bytes. For classifiers and classification metrics, labels encoded
  as bytes is deprecated and will raise an error in v1.7.
  :pr:`18555` by :user:`Kaushik Amar Das <cozek>`.

- |Fix| :func:`~utils._safe_indexing` now works correctly for polars DataFrame when
  `axis=0` and supports indexing polars Series.
  :pr:`28521` by :user:`Yao Xiao <Charlie-XIAO>`.

.. rubric:: Code and documentation contributors

Thanks to everyone who has contributed to the maintenance and improvement of
the project since version 1.4, including:

TODO: update at the time of the release.
