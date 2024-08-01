from prefect import task, Flow
import model  # This imports the training function

@task
def retrain_model():
    model.train_and_save_model()

with Flow("retrain_and_redeploy") as flow:
    retrain_model()

if __name__ == "__main__":
    flow.run()
