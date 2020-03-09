# Shrek Fans Only

The problem prompt hinted heavily that this challenge would involve plundering Git data. Inspection of HTML source revealed a pretty obvious LFI, which would be our engine for reading data from the `.git/` directory structure.

For most Git-plundering-related challenges, I rely on [this blog post](http://web.archive.org/web/20200307035838/https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/). A somwhat automated version the blog post's process applied to this challenge is implemented in this [solution script](./solve.py).
