package tasks

import "testing"
import "gopkg.in/mgo.v2"
import "fmt"

func TestCRUD(t *testing.T) {
	sess, err := mgo.Dial("localhost:27017")
	if err != nil {
		t.Fatalf("error dialing Mongo: %v", err)
	}
	defer sess.Close()

	store := &MongoStore{
		Session:        sess,
		DatabaseName:   "test",
		CollectionName: "tasks",
	}

	newtask := &NewTask{
		Title: "Learn MongoDB",
		Tags:  []string{"mongo", "info344"},
	}
	task, err := store.Insert(newtask)
	if err != nil {
		t.Errorf("error insterting new task: %v", err)
	}
	fmt.Println(task.ID)

	task2, err := store.Get(task.ID)
	if err != nil {
		t.Errorf("task title didn't match, expected %s but got %s", task.Title, task2.Title)
	}

	sess.DB(store.DatabaseName).C(store.CollectionName).RemoveAll(nil)

}
