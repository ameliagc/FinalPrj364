This application uses the New York Times archive API to allow users to search and view articles from a specified month and year, going back to the year 1851. 

The user must search for the article in the following format: YYYY M (ex. for January 2017, it would be 2017 1).

If the year/month has already been searched for, the user is brought to the list of articles.

If a new year/month is searched, an article is added to the list of searched articles and the user can click the link to see this list.

The list of searched articles displays each headline and a link to that article on the New York Times website.

If a user creates an account and logs in, they can create a collection to save their favorite articles by selecting from the list of articles they have already searched for.

Before running the code, you need to create the database "articles" by running the line of code: createdb articles

To run the code: python mainapp.py runserver

The user can configure an email by exporting their username and password through terminal when running the application if they want to receieve emails when a new article is added to the list. If this is configured, the user will receieve an email from the Admin ameliagc364@gmail.com whenever a new year/month is searched for and a new article is added.

The app is deployed to Heroku at the following URL: http://nytimes-article-search.herokuapp.com/.

The dependencies to pip install are specified in the requirements.txt file.