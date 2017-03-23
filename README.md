This branch attempts to patch miniconda.

Disclaimer: work in progress, do not attempt to use for any purpose.

Strategy:
 - copy pywebcorp folder into conda's Lib\site-packages\
 - append `import pywebcorp.https` to Lib\site-packages\requests\__init__.py

Then use conda as normal. For example, in a cmd.exe terminal:

```
> conda create -n cosy
> activate cosy
(cosy) > python
>>> import cloudpickle
ImportError: No module named cloudpickle
>>> exit()
(cosy) > conda install cloudpickle
(cosy) > python
>>> import cloudpickle
>>> cloudpickle.__version__
'0.2.2'
```


Note, may still have general issues to work-around, e.g. with conda DLLs in some versions of windows.

