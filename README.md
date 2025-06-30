# cpr-cagateway-template

## Template for new CA Gateway integrations

### Use this repository to create new integrations for new CA Gateway integration types. 


1. [Use this repository](#using-the-repository)
1. [Update the integration-manifest.json](#updating-the-integration-manifest.json)
1. [Add Keyfactor Bootstrap Workflow (keyfactor-bootstrap-workflow.yml)](#add-bootstrap)
1. [Create required branches](#create-required-branches)
1. [Replace template files/folders](#replace-template-files-and-folders)
1. [Create initial prerelease](#create-initial-prerelease)
---

#### Using the repository
1. Select the ```Use this template``` button at the top of this page
1. Update the repository name following [these guidelines](https://keyfactorinc.sharepoint.com/sites/IntegrationWiki/SitePages/GitHub-Processes.aspx#repository-naming-conventions) 
    1. All repositories must be in lower-case
	1. General pattern: company-product-type
	1. e.g. hashicorp-vault-orchestator
1. Click the ```Create repository``` button

---

#### Updating the integration-manifest.json

*The following properties must be updated in the integration-manifest.json*

Clone the repository locally, use vsdev.io, or the GitHub online editor to update the file.

* "name": "Friendly name for the integration"
	* This will be used in the readme file generation and catalog entries
* "description": "Brief description of the integration."
	* This will be used in the readme file generation
	* If the repository description is empty this value will be used for the repository description upon creating a release branch
* "release_dir": "PATH\\\TO\\\BINARY\\\RELEASE\\\OUTPUT\\\FOLDER"
	* Path separators can be "\\\\" or "/"
	* Be sure to specify the release folder name. This can be found by running a Release build and noting the output folder
	* Example: "AzureAppGatewayOrchestrator\\bin\\Release"
* "gateway_framework": "" string denoting the required command gateway framework version
---

#### Add Bootstrap 
Add Keyfactor Bootstrap Workflow (keyfactor-bootstrap-workflow.yml). This can be copied directly from the workflow templates or through the Actions tab
* Directly:
    1. Create a file named ```.github\workflows\keyfactor-bootstrap-workflow.yml``` 
	1. Copy the contents of [keyfactor/.github/workflow-templates/keyfactor-bootstrap-workflow.yml](https://raw.githubusercontent.com/Keyfactor/.github/main/workflow-templates/keyfactor-bootstrap-workflow.yml) into the file created in the previous step
* Actions tab:
    1. Navigate to the [Actions tab](./actions) in the new repository
	1. Click the ```New workflow``` button
	1. Find the ```Keyfactor Bootstrap Workflow``` and click the ```Configure``` button
	1. Click the ```Commit changes...``` button on this screen and the next to add the bootstrap workflow to the main branch
	
A new build will run the tasks of a *Push* trigger on the main branch

*Ensure there are no errors during the workflow run in the Actions tab.*

---

#### Create required branches 
1. Create a release branch from main: release-1.0
1. Create a dev branch from the starting with the devops id in the format ab#\<DevOps-ID>, e.g. ab#53535. 
    1. For the cleanest pull request merge, create the dev branch from the release branch. 
	1. Optionally, add a suffix to the branch name indicating initial release. e.g. ab#53535-initial-release

---


#### Replace template files and folders
1. Replace the contents of readme_source.md
1. Create a CHANGELOG.md file in the root of the repository indicating ```1.0: Initial release```
1. Replace the SampleOrchestratorExtension.sln solution file and SampleOrchestratorExtension folder with your new orchestrator dotnet solution
1. Push your updates to the dev branch (ab#xxxxx)

---


#### Create initial prerelease
1. Create a pull request from the dev branch to the release-1.0 branch


----

When the repository is ready for SE Demo, change the following property:
* "status": "pilot"

When the integration has been approved by Support and Delivery teams, change the following property:
* "status": "production"

If the repository is ready to be published in the public catalog, the following properties must be updated:
* "update_catalog": true
* "link_github": true
