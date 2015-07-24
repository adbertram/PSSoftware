# SoftwareInstallManager PowerShell Module

> A single way to install, uninstall, upgrade and configure software with a single framework.

SoftwareInstallManager is a PowerShell module born from necessity. It was built to create a single tool deploy and manage software. No longer do you have to remember:

```
msiexec.exe /i somemsi.msi /qn /Lvx* C:\Windows\Temp\install.log 
```

...just to deploy a single MSI. SoftwareInstallManager simplifies that complexity to just:

```
Install-Software -MsiInstallerFilePath somemsi.msi
```

This is what SoftwareInstallManager is all about. Removing the complexities of software management.

## Version Support

| PSv1 | PSv2 | PSv3 | PSv4 | PSv5 
|-----|------|------|--------|-------|---------|-
| No   | Yes    | Yes    | Yes      | Untested

## Getting Started

### Download

You can [download](https://github.com/adbertram/SoftwareInstallManager/archive/master.zip)
this repository.

### Import

Once you've downloaded the repo place the SoftwareInstallManager folder in any path in your ``$PSModulePath``. I recommend copying it to either ``C:\Program Files\WindowsPowerShell\Modules`` or ``C:\Users\<Username>\Documents\WindowsPowerShell\Modules``.

Once it's in one of those paths you can either import it manually by ``Import-Module SoftwareInstallManager`` or rely on auto-module loading.


### What's included

In the repo you'll find the following files.

| File/Folder     | Provides                                       |
|-----------------|------------------------------------------------|
| CONTRIBUTING.md | MDL contribution guidelines.                   |
| docs            | Files for the documentation site.              |
| gulpfile.js     | gulp configuration for MDL.                    |
| LICENSE         | Project license information.                   |
| package.json    | npm package information.                       |
| README.md       | Details for quickly understanding the project. |
| src             | Source code for MDL components.                |
| templates       | Example templates.                             |
| test            | Project test files.                            |

### Build

To get started modifying the components or the docs, first install the necessary
dependencies, from the root of the project:

```bash
npm install && npm install -g gulp
```

> MDL requires NodeJS 0.12.

Next, run the following one-liner to compile the components and the docs and
spawn a local instance of the documentation site:

```bash
gulp serve
```

Most changes made to files inside the `src` or the `docs` directory will cause
the page to reload. This page can also be loaded up on physical devices thanks
to BrowserSync.

To build a production version of the components, run:

```bash
gulp
```

This will clean the `dist` folder and rebuild the assets for serving.


### Templates

The `templates/` subdirectory contains a few exemplary usages of MDL. Templates
have their own, quasi-separate gulp pipeline and can be compiled with
`gulp templates`. The templates use the vanilla MDL JS and
[themed](http://www.getmdl.io/customize/index.html) CSS files. Extraneous styles
are kept in a separate CSS file. Use `gulp serve` to take a look at the
templates:

* [Blog Template](http://www.getmdl.io/templates/blog)
* [Dashboard Template](http://www.getmdl.io/templates/dashboard)
* [Text Heavy Webpage Template](http://www.getmdl.io/templates/text-only)
* [Stand Alone Article Template](http://www.getmdl.io/templates/article)
* [Android.com MDL Skin Template](http://www.getmdl.io/templates/android-dot-com)

> Templates are not officially supported in IE9 and legacy browsers that do not
pass the minimum-requirements defined in our
[cutting-the-mustard test](https://github.com/google/material-design-lite/blob/master/src/mdlComponentHandler.js#L262-L275).

## Versioning

For transparency into our release cycle and in striving to maintain backward
compatibility, Material Design Lite is maintained under
[the Semantic Versioning guidelines](http://semver.org/). Sometimes we screw up,
but we'll adhere to those rules whenever possible.

## Feature requests

If you find MDL doesn't contain a particular component you think would be
useful, please check the issue tracker in case work has already started on it.
If not, you can request a [new component](https://github.com/Google/material-design-lite/issues/new?title=[Component%20Request]%20{Component}&body=Please%20include:%0A*%20Description%0A*%20Material%20Design%20Spec%20link%0A*%20Use%20Case%28s%29).
Please keep in mind that one of the goals of MDL is to adhere to the Material
Design specs and therefore some requests might not be within the scope of this
project.

## Do you include any features that a framework comes with?

Material Design Lite is focused on delivering a vanilla CSS/JS/HTML library of
components. We are not a framework. If you are building a single-page app and
require features like two-way data-binding, templating, CSS scoping and so
forth, we recommend trying out the excellent [Polymer](http://polymer-project.org) project.


## License

© Google, 2015. Licensed under an [Apache-2](https://github.com/google/material-design-lite/blob/master/LICENSE) license.
