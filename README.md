# jupyterlabdemo

## Running

* `docker run -it --rm -p 8000:8000 --name jupyterlabdemo
  lsstsqre/jupyterlabdemo`
   
* Go to `http://localhost:8000` and log in as `jupyterlab`, any password
  or none (obviously this is not going to stick around to production).
  
### Notebook

* Choose `LSST_Stack` as your Python kernel.  Then you can `import lsst`
  and the stack and all its pre-reqs are available in the environment.
  
### Terminal

* Start by running `. /opt/lsst/software/stack/loadLSST.bash`.  Then
  `setup lsst_distrib` and then you're in a stack shell environment.

## Building

* `docker build -t lsstsqre/jupyterlabdemo .`
